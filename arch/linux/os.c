#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>

#include "../platform.h"

void ptlib_prepare( pid_t pid )
{
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE);
}

int ptlib_wait( pid_t *pid, int *status, long *ret )
{
    *pid=wait(status);

    if( WIFEXITED(*status) ) {
        *ret=WEXITSTATUS(*status);
        return EXIT;
    } else if( WIFSIGNALED(*status) ) {
        *ret=WTERMSIG(*status);
        return SIGEXIT;
    } else if( WIFSTOPPED(*status) ) {
        *ret=WSTOPSIG(*status);

        if( *ret==(SIGTRAP | PTRACE_EVENT_FORK << 8) || *ret==(SIGTRAP | PTRACE_EVENT_VFORK << 8) ||
            *ret==(SIGTRAP | PTRACE_EVENT_CLONE << 8) ) {

            ptrace(PTRACE_GETEVENTMSG, *pid, NULL, ret);
            return NEWPROCESS;
        }
        if( *ret==SIGTRAP ) {
            /* Since we cannot reliably know when PTRACE_O_TRACESYSGOOD is supported, we always assume that's the reason for a
             * SIGTRACE */
            *ret=ptlib_get_syscall(*pid);
            return SYSCALL;
        }

        return SIGNAL;
    } else {
        /* What is going on here? We should never get here. */
        abort();
    }
}

int ptlib_reinterpret( enum PTLIB_WAIT_RET prevstate, pid_t pid, int status, long *ret )
{
    // Previous state does not affect us
    // XXX if the first thing the child does is a "fork", is this statement still true?
    return prevstate;
}
