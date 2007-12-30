#include "config.h"

// XXX Should move the generation of _BSD_SOURCE into autoconf
#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include <ext/hash_map>

#include <stdio.h>
#include <assert.h>

#include "arch/platform.h"

#include "syscalls.h"
#include "parent.h"

// Keep track of handled syscalls


// Keep track of the states for the various processes
static __gnu_cxx::hash_map<pid_t, pid_state> state;

static __gnu_cxx::hash_map<int, syscall_hook> syscalls;

bool sys_geteuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, 0 );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_getuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, 0 );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

static void init_handlers()
{
    syscalls[SYS_geteuid32]=syscall_hook(sys_geteuid, "geteuid");
    syscalls[SYS_getuid32]=syscall_hook(sys_getuid, "getuid");
#if ! PTLIB_SUPPORTS_FORK
    syscalls[SYS_fork]=syscall_hook(sys_fork, "fork");
#endif
#if ! PTLIB_SUPPORTS_VFORK
    syscalls[SYS_vfork]=sys_vfork;
#endif
#if ! PTLIB_SUPPORTS_CLONE
    syscalls[SYS_clone]=sys_clone;
#endif

    syscalls[SYS_stat64]=syscall_hook(sys_stat64, "stat64");
    syscalls[SYS_fstat64]=syscall_hook(sys_stat64, "fstat64");
    syscalls[SYS_lstat64]=syscall_hook(sys_stat64, "lstat64");

    syscalls[SYS_chmod]=syscall_hook(sys_chmod, "chmod");
    syscalls[SYS_fchmod]=syscall_hook(sys_chmod, "fchmod");

    syscalls[SYS_mmap]=syscall_hook(sys_mmap, "mmap");
}

static void handle_exit( pid_t pid, int status, const struct rusage &usage )
{
    // Let's see if the process doing the exiting is even registered
     __gnu_cxx::hash_map<pid_t, pid_state>::iterator process=state.find(pid);
     assert(process!=state.end());

    // This function is fairly empty if the platform does not require "wait" emulation
#if !PTLIB_PARENT_CAN_WAIT
#error emulating parent wait not yet implemented
#endif // PTLIB_PARENT_CAN_WAIT

    state.erase(process);
}

static void handle_new_process( pid_t parent, pid_t child )
{
#if !PTLIB_PARENT_CAN_WAIT
    state[child].parent=parent;
#error emulating parent wait not yet implemented
#endif // PTLIB_PARENT_CAN_WAIT
}

int process_children(pid_t first_child, int comm_fd )
{
    // Create a state for the first child

    state[first_child]=pid_state();
    init_handlers();

    dlog( "Begin the process loop\n" );

    int num_processes=1;

    while(num_processes>0) {
        int status;
        pid_t pid;
        long ret;
        int sig=0;
        
        enum PTLIB_WAIT_RET wait_state=static_cast<enum PTLIB_WAIT_RET>(ptlib_wait( &pid, &status, &ret ));

        // If this is the first time we see this process, we need to init the ptrace options for it
        if( state[pid].state==pid_state::INIT ) {
            dlog( "%d: Init new process\n", pid);

            ptlib_prepare(pid);
            state[pid].state=pid_state::NONE;

            wait_state=static_cast<enum PTLIB_WAIT_RET>(ptlib_reinterpret( wait_state, pid, status, &ret ));
        }

        switch(wait_state) {
        case SYSCALL:
            {
                pid_state *proc_state=&state[pid];
                if( proc_state->state==pid_state::REDIRECT ) {
                    dlog("%d: Called syscall %d, redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );

                    if( !syscalls[ret].func( ret, pid, proc_state ) )
                        sig=-1; // Mark for ptrace not to continue the process
                } else if( syscalls.find(ret)!=syscalls.end() ) {
                    dlog("%d: Called %s\n", pid, syscalls[ret].name);

                    if( !syscalls[ret].func( ret, pid, proc_state ) )
                        sig=-1; // Mark for ptrace not to continue the process
                } else {
                    dlog("%d: Unknown syscall %ld\n", pid, ret);
                }
            }
            break;
        case SIGNAL:
            dlog("%d: Signal %ld\n", pid, ret);
            sig=ret;
            break;
        case EXIT:
        case SIGEXIT:
            {
                if( wait_state==EXIT )
                    dlog("%d: Exit with return code %ld\n", pid, ret);
                else
                    dlog("%d: Exit with signal %ld\n", pid, ret);

                struct rusage rusage;
                getrusage( RUSAGE_CHILDREN, &rusage );
                handle_exit(pid, status, rusage );
                if( pid==first_child && comm_fd!=-1 ) {
                    write( comm_fd, &status, sizeof(status) );
                    close( comm_fd );
                    comm_fd=-1;
                }

                num_processes--;
            }
            break;
        case NEWPROCESS:
            {
                dlog("%d: Created new child process %ld\n", pid, ret);
                handle_new_process( pid, ret );
                num_processes++;
            }
        }

        // The show must go on
        if( sig>=0 )
            ptrace(PTRACE_SYSCALL, pid, 0, sig);
    }

    return 0;
}

bool allocate_process_mem( pid_t pid, pid_state *state, int sc_num )
{
    dlog("allocate_process_mem: %d running syscall %d needs process memory\n", pid, sc_num );

    // Save the old state
    ptlib_save_state( pid, state->saved_state );
    state->orig_sc=sc_num;
    state->state=pid_state::ALLOCATE;

    // Translate the whatever call into an mmap
    ptlib_set_syscall( pid, SYS_mmap );

    if( ptlib_set_argument( pid, 1, 0 ) ) // start pointer
        dlog("allocate_process_mem: %d set mmap arg 1\n", pid );
    if( ptlib_set_argument( pid, 2, (void *)sysconf(_SC_PAGESIZE) ) ) // Length of page - we allocate exactly one page
        dlog("allocate_process_mem: %d set mmap arg 2\n", pid );
    if( ptlib_set_argument( pid, 3, (void *)(PROT_EXEC|PROT_READ|PROT_WRITE) ) ) // Protection - allow execute
        dlog("allocate_process_mem: %d set mmap arg 3\n", pid );
    if( ptlib_set_argument( pid, 4, (void *)(MAP_PRIVATE|MAP_ANONYMOUS) ) ) // Flags - anonymous memory allocation
        dlog("allocate_process_mem: %d set mmap arg 4\n", pid );
    if( ptlib_set_argument( pid, 5, (void *)-1 ) ) // File descriptor
        dlog("allocate_process_mem: %d set mmap arg 5\n", pid );
    if( ptlib_set_argument( pid, 6, 0 ) ) // Offset
        dlog("allocate_process_mem: %d set mmap arg 6\n", pid );

    dlog("Calling mmap(%p, %p, %p, %p, %p, %p)\n", ptlib_get_argument( pid, 1 ), ptlib_get_argument( pid, 2 ), ptlib_get_argument( pid, 3 ), ptlib_get_argument( pid, 4 ), ptlib_get_argument( pid, 5 ), ptlib_get_argument( pid, 6 ) );
    return true;
}

bool sys_mmap( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        dlog("mmap: %d direct call\n", pid);
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        dlog("mmap: %d direct return\n", pid);
        state->state=pid_state::NONE;
    } else if( state->state==pid_state::ALLOCATE ) {
        state->state=pid_state::NONE;

        if( ptlib_success( pid, sc_num ) ) {
            state->memory=ptlib_get_retval( pid );
            state->mem_size=sysconf( _SC_PAGESIZE );
            dlog("mmap: %d allocated for our use %d bytes at %p\n", state->mem_size, state->memory);
            
            ptlib_prepare_memory( pid, &state->memory, &state->mem_size );

            // Memory is prepared, we can now use it to restart the original system call
            ptlib_restore_state( pid, state->saved_state );
            return ptlib_generate_syscall( pid, state->orig_sc , state->memory );
        } else {
            // The allocation failed. What can you do except kill the process?
            dlog("mmap: %d our memory allocation failed with error. Kill process. %d\n", pid, ptlib_get_error(pid, sc_num) );
            ptrace( PTRACE_KILL, pid, 0, 0 );
            return false;
        }
    }

    return true;
}
