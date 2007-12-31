/*
    Fakeroot Next Generation - run command with fake root privileges
    This program is copyrighted. Copyright information is available at the
    AUTHORS file at the root of the source tree for the fakeroot-ng project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
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

// forward declaration of function
static bool finish_allocation( int sc_num, pid_t pid, pid_state *state );


// Keep track of handled syscalls


// Keep track of the states for the various processes
static __gnu_cxx::hash_map<pid_t, pid_state> state;

static __gnu_cxx::hash_map<int, syscall_hook> syscalls;

static void init_handlers()
{
    syscalls[SYS_geteuid32]=syscall_hook(sys_getuid, "geteuid");
    syscalls[SYS_getuid32]=syscall_hook(sys_getuid, "getuid");
    syscalls[SYS_getegid32]=syscall_hook(sys_getuid, "getegid");
    syscalls[SYS_getgid32]=syscall_hook(sys_getuid, "getgid");

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

    syscalls[SYS_chown32]=syscall_hook(sys_chown, "chown32");
    syscalls[SYS_fchown32]=syscall_hook(sys_chown, "fchown32");
    syscalls[SYS_lchown32]=syscall_hook(sys_chown, "lchown32");

    syscalls[SYS_chmod]=syscall_hook(sys_chmod, "chmod");
    syscalls[SYS_fchmod]=syscall_hook(sys_chmod, "fchmod");

    syscalls[SYS_mmap2]=syscall_hook(sys_mmap, "mmap2");
}

static const char *sig2str( int signum )
{
    static char buffer[64];

    switch(signum) {
#define SIGNAME(a) case a: return #a;
        SIGNAME(SIGHUP);
        SIGNAME(SIGINT);
        SIGNAME(SIGQUIT);
        SIGNAME(SIGILL);
        SIGNAME(SIGTRAP);
        SIGNAME(SIGABRT);
        SIGNAME(SIGBUS);
        SIGNAME(SIGFPE);
        SIGNAME(SIGKILL);
        SIGNAME(SIGSEGV);
        SIGNAME(SIGPIPE);
        SIGNAME(SIGALRM);
        SIGNAME(SIGTERM);
        SIGNAME(SIGCHLD);
        SIGNAME(SIGCONT);
        SIGNAME(SIGSTOP);
#undef SIGNAME
    default:
        sprintf(buffer, "signal %d", signum);
    }

    return buffer;
}

static const char *state2str( pid_state::states state )
{
    static char buffer[64];

    switch(state) {
#define STATENAME(a) case pid_state::a: return #a;
        STATENAME(INIT)
        STATENAME(NONE)
        STATENAME(RETURN)
        STATENAME(REDIRECT1)
        STATENAME(REDIRECT2)
        STATENAME(ALLOCATE)
        STATENAME(ALLOC_RETURN)
#undef STATENAME
    }

    sprintf(buffer, "Unknown state %d", state);

    return buffer;
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
                if( proc_state->state==pid_state::REDIRECT1 || proc_state->state==pid_state::REDIRECT2 ) {
                    dlog("%d: Called syscall %d, redirected from %s\n", pid, ret, syscalls[proc_state->orig_sc].name );

                    if( !syscalls[proc_state->orig_sc].func( ret, pid, proc_state ) )
                        sig=-1; // Mark for ptrace not to continue the process
                } else if( proc_state->state==pid_state::ALLOC_RETURN ) {
                    if( !finish_allocation( ret, pid, proc_state ) )
                        sig=-1;
                } else if( syscalls.find(ret)!=syscalls.end() ) {
                    dlog("%d: Called %s(%s)\n", pid, syscalls[ret].name, state2str(proc_state->state));

                    if( !syscalls[ret].func( ret, pid, proc_state ) )
                        sig=-1; // Mark for ptrace not to continue the process
                } else {
                    dlog("%d: Unknown syscall %ld(%s)\n", pid, ret, state2str(proc_state->state));
                }
            }
            break;
        case SIGNAL:
            dlog("%d: Signal %s\n", pid, sig2str(ret));
            sig=ret;
            break;
        case EXIT:
        case SIGEXIT:
            {
                if( wait_state==EXIT )
                    dlog("%d: Exit with return code %ld\n", pid, ret);
                else {
                    dlog("%d: Exit with %s\n", pid, sig2str(ret));
                }

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
    ptlib_set_syscall( pid, SYS_mmap2 );

    ptlib_set_argument( pid, 1, 0 ); // start pointer
    ptlib_set_argument( pid, 2, (void *)sysconf(_SC_PAGESIZE) ); // Length of page - we allocate exactly one page
    ptlib_set_argument( pid, 3, (void *)(PROT_EXEC|PROT_READ|PROT_WRITE) ); // Protection - allow execute
    ptlib_set_argument( pid, 4, (void *)(MAP_PRIVATE|MAP_ANONYMOUS) ); // Flags - anonymous memory allocation
    ptlib_set_argument( pid, 5, (void *)-1 ); // File descriptor
    ptlib_set_argument( pid, 6, 0 ); // Offset

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

        if( ptlib_success( pid, sc_num ) ) {
            state->memory=ptlib_get_retval( pid );
            state->mem_size=sysconf( _SC_PAGESIZE );
            dlog("mmap: %d allocated for our use %d bytes at %p\n", pid, state->mem_size, state->memory);
            
            ptlib_prepare_memory( pid, &state->memory, &state->mem_size );

            // Memory is prepared, we can now use it to restart the original system call
            state->state=pid_state::ALLOC_RETURN;
            return ptlib_generate_syscall( pid, state->orig_sc , state->memory );
        } else {
            // The allocation failed. What can you do except kill the process?
            dlog("mmap: %d our memory allocation failed with error. Kill process. %d\n", pid, ptlib_get_error(pid, sc_num) );
            ptrace( PTRACE_KILL, pid, 0, 0 );
            return false;
        }
        state->state=pid_state::NONE;
    }

    return true;
}

static bool finish_allocation( int sc_num, pid_t pid, pid_state *state )
{
    ptlib_restore_state( pid, state->saved_state );
    state->state=pid_state::NONE;

    syscall_hook *sys=&syscalls[sc_num];
    dlog("finish_allocation: %d restore state and call %s handler\n", pid, sys->name );

    return sys->func( sc_num, pid, state );
}
