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

int ptlib_linux_continue( int request, pid_t pid, int signal )
{
    return ptrace( request, pid, 0, signal );
}

void ptlib_linux_prepare( pid_t pid )
{
    if( ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE)!=0 )
        perror("PTRACE_SETOPTIONS failed");
}

int ptlib_linux_wait( pid_t *pid, int *status, ptlib_extra_data *data )
{
    *pid=wait4(-1, status, 0, data );

    return *pid!=-1;
}


long ptlib_linux_parse_wait( pid_t pid, int status, enum PTLIB_WAIT_RET *type )
{
    long ret;

    if( WIFEXITED(status) ) {
        ret=WEXITSTATUS(status);
        *type=EXIT;
    } else if( WIFSIGNALED(status) ) {
        ret=WTERMSIG(status);
        *type=SIGEXIT;
    } else if( WIFSTOPPED(status) ) {
        ret=WSTOPSIG(status);

        if( ret==SIGTRAP ) {
            siginfo_t siginfo;

            if( ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)==0 &&
                (siginfo.si_code>>8==PTRACE_EVENT_FORK || siginfo.si_code>>8==PTRACE_EVENT_VFORK ||
                 siginfo.si_code>>8==PTRACE_EVENT_CLONE ) )
            {
                ptrace( PTRACE_GETEVENTMSG, pid, NULL, &ret );

                *type=NEWPROCESS;
            } else {
                /* Since we cannot reliably know when PTRACE_O_TRACESYSGOOD is supported, we always assume that's the reason for a
                 * SIGTRACE */
                ret=ptlib_get_syscall(pid);
                *type=SYSCALL;
            }
        } else {
            dlog("stopped with some other signal\n");
            *type=SIGNAL;
        }
    } else {
        /* What is going on here? We should never get here. */
        dlog("Process %d received unknown status %x - aborting\n", pid, status);
        dlog(NULL); /* Flush the log before we abort */
        abort();
    }

    return ret;
}

int ptlib_linux_reinterpret( enum PTLIB_WAIT_RET prevstate, pid_t pid, int status, long *ret )
{
    // Previous state does not affect us
    // XXX if the first thing the child does is a "fork", is this statement still true?
    return prevstate;
}

int ptlib_linux_get_mem( pid_t pid, void *process_ptr, void *local_ptr, size_t len )
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

int ptlib_linux_set_mem( pid_t pid, const void *local_ptr, void *process_ptr, size_t len )
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

int ptlib_linux_get_string( pid_t pid, void *process_ptr, char *local_ptr, size_t maxlen )
{
    /* Are we aligned on the "start" front? */
    int offset=((unsigned long)process_ptr)%sizeof(long);
    process_ptr-=offset;
    int i=0;
    int done=0;
    int word_offset=0;

    while( !done ) {
        unsigned long word=ptrace( PTRACE_PEEKDATA, pid, process_ptr+(word_offset++)*sizeof(long), 0 );

        while( !done && offset<sizeof(long) && i<maxlen ) {
            local_ptr[i]=((char *)&word)[offset]; /* Endianity neutral copy */

            done=local_ptr[i]=='\0';
            ++i;
            ++offset;
        }

        offset=0;
        done=done || i>=maxlen;
    }

    return i;
} 

#if 0
// No definition just yet
int ptlib_linux_set_string( pid_t pid, const char *local_ptr, void *process_ptr )
{
}
#endif
