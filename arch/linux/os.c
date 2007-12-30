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

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "../platform.h"

void ptlib_prepare( pid_t pid )
{
    if( ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE)!=0 )
        perror("PTRACE_SETOPTIONS failed");
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

        if( *ret==SIGTRAP ) {
            siginfo_t siginfo;

            if( ptrace(PTRACE_GETSIGINFO, *pid, NULL, &siginfo)==0 &&
                (siginfo.si_code>>8==PTRACE_EVENT_FORK || siginfo.si_code>>8==PTRACE_EVENT_VFORK ||
                 siginfo.si_code>>8==PTRACE_EVENT_CLONE ) )
            {
                ptrace( PTRACE_GETEVENTMSG, *pid, NULL, ret );

                return NEWPROCESS;
            }

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

int ptlib_get_mem( pid_t pid, void *process_ptr, void *local_ptr, size_t len )
{
    int i;
    errno=0;

    for( i=0; i<len/sizeof(long) && errno==0; ++i ) {
        ((long *)local_ptr)[i]=ptrace(PTRACE_PEEKDATA, pid, process_ptr+i*sizeof(long));
    }

    /* Unaligned data lengths not yet supported */
    assert(len%sizeof(long)==0);

    return errno==0;
}

int ptlib_set_mem( pid_t pid, const void *local_ptr, void *process_ptr, size_t len )
{
    int i;
    errno=0;

    for( i=0; i<len/sizeof(long) && errno==0; ++i ) {
        ptrace(PTRACE_POKEDATA, pid, process_ptr+i*sizeof(long), ((long *)local_ptr)[i]);
    }

    /* Unaligned data lengths not yet supported */
    assert(len%sizeof(long)==0);

    return errno==0;
}
