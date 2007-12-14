#include "config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#include <ext/hash_map>

#include <stdio.h>

#include "arch/platform.h"

#include "syscalls.h"
#include "parent.h"

// Keep track of handled syscalls


// Keep track of the states for the various processes
static __gnu_cxx::hash_map<pid_t, pid_state> state;

static __gnu_cxx::hash_map<int, sys_callback> syscalls;

void sys_geteuid( pid_t pid, pid_state *state )
{
    if( state->state==pid_state::RETURN ) {
        ptlib_set_retval( pid, 0 );
    }
}

void sys_getuid( pid_t pid, pid_state *state )
{
    if( state->state==pid_state::RETURN ) {
        ptlib_set_retval( pid, 0 );
    }
}

static void init_handlers()
{
    syscalls[__NR_geteuid32]=sys_geteuid;
    syscalls[__NR_getuid32]=sys_getuid;
    syscalls[__NR_fork]=sys_fork;
}

int process_children(pid_t first_child)
{
    // Create a state for the first child

    state[first_child]=pid_state();
    init_handlers();

    int statd;
    wait(&statd);
    ptlib_prepare(first_child);
    ptrace(PTRACE_SYSCALL, first_child, 0, 0 );

    while(1) {
        int status;
        pid_t ret=wait(&status);
        // printf("Wait returned with pid %d, status: 0x%08x\n", ret, status);

        if( WIFEXITED(status) ) {
            return WEXITSTATUS(status);
        } else if( WIFSIGNALED(status) ) {
            printf("Process %d exited with signal %d\n", ret, WTERMSIG(status) );

            return -1;
        } else if( WIFSTOPPED(status) ) {
            int sig = WSTOPSIG(status);
            // printf("Process %d halted due to signal %d\n", ret, sig );
            if( sig==SIGTRAP ) {
                int syscall=(int)ptlib_get_syscall(ret);

                if( syscalls.find(syscall)!=syscalls.end() ) {
                    pid_state *process_state=&state[ret];
                    syscalls[syscall]( ret, process_state );

                    switch( process_state->state ) {
                    case pid_state::NONE:
                        process_state->state=pid_state::RETURN;
                        break;
                    case pid_state::RETURN:
                        process_state->state=pid_state::NONE;
                        break;
                    }
                }
                sig=0;
            } else {
                printf("Process received signal %d\n", sig);
            }
            ptrace( PTRACE_SYSCALL, ret, 0, sig );
        } else {
            printf("Unknown meaning of status\n");
        }
    }

    return 0;
}
