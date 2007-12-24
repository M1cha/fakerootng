#include "config.h"

// XXX Should move the generation of _BSD_SOURCE into autoconf
#define _BSD_SOURCE

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

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

bool sys_geteuid( pid_t pid, pid_state *state )
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

bool sys_getuid( pid_t pid, pid_state *state )
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
    syscalls[__NR_geteuid32]=syscall_hook(sys_geteuid, "geteuid");
    syscalls[__NR_getuid32]=syscall_hook(sys_getuid, "getuid");
#if ! PTLIB_SUPPORTS_FORK
    syscalls[__NR_fork]=syscall_hook(sys_fork, "fork");
#endif
#if ! PTLIB_SUPPORTS_VFORK
    syscalls[__NR_vfork]=sys_vfork;
#endif
#if ! PTLIB_SUPPORTS_CLONE
    syscalls[__NR_clone]=sys_clone;
#endif
}

static void handle_exit( pid_t pid, int status, const struct rusage &usage )
{
    // Let's see if the process doing the exiting is even registered
     __gnu_cxx::hash_map<pid_t, pid_state>::iterator process=state.find(pid);
     assert(process!=state.end());

    // Does it have a parent at all?
    if( process->second.parent==1 )
        return;

    switch( state[process->second.parent].state ) {
        // XXX This is a very simplistic approach. No support for waiting for specific groups/pid, and no handling of waitid
    case pid_state::WAIT_HALTED:
        {
            void *process_status=ptlib_get_argument(process->second.parent, 1);
            ptrace(PTRACE_POKEDATA, process->second.parent, process_status, status); // Write the status as we got it
            ptrace(PTRACE_SYSCALL, process->second.parent, 0, 0); // Continue the halted process
        }
        break;
    case pid_state::WAIT4_HALTED:
    case pid_state::WAITPID_HALTED:
        {
            void *process_status=ptlib_get_argument(process->second.parent, 2);
            ptrace(PTRACE_POKEDATA, process->second.parent, process_status, status); // Write the status as we got it
            ptrace(PTRACE_SYSCALL, process->second.parent, 0, 0); // Continue the halted process
        }
        break;
    default:
        // Parent was not waiting for us. Add this event to the end of the "waiting" list
        state[process->second.parent].waiting_signals.push_back(pid_state::waiting_signal(pid, status, usage));
        break;
    }
}

static void handle_new_process( pid_t parent, pid_t child )
{
    state[child].parent=parent;
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
            if( syscalls.find(ret)!=syscalls.end() ) {
                dlog("%d: Called %s\n", pid, syscalls[ret].name);

                if( !syscalls[ret].func( pid, &state[pid] ) )
                    sig=-1; // Mark for ptrace not to continue the process
            } else {
                dlog("%d: Unknown syscall %ld\n", pid, ret);
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
