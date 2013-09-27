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
#include <sched.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "../platform.h"
#include "os.h"

// Some ptrace command enums are doubly defined, once as enums and once as preprocessor. Type safety requires we use
// the later
#undef PTRACE_GETREGS
#undef PTRACE_GETSIGINFO
#undef PTRACE_GETEVENTMSG
#undef PTRACE_PEEKDATA
#undef PTRACE_POKEDATA

namespace ptlib {
namespace linux {

std::thread::id master_thread;

static struct {
    callback_initiator callback;
} thread_proxy;

void init( const callback_initiator &callback )
{
    thread_proxy.callback = callback;
    master_thread = std::this_thread::get_id();
}

int cont( __ptrace_request request, pid_t pid, int signal )
{
    return ptrace( request, pid, 0, signal );
}

void prepare( pid_t pid )
{
    // These cause more harm than good
    //if( ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE)!=0 )
    //    perror("PTRACE_SETOPTIONS failed");
}

bool wait( pid_t *pid, int *status, extra_data *data, int async )
{
    ASSERT_MASTER_THREAD();
    *pid=wait4(-1, status, (async?WNOHANG:0)|__WALL, data );

    if( async && *pid==0 ) {
        errno=EAGAIN;
        *pid=-1;
    }

    return *pid!=-1;
}


long parse_wait( pid_t pid, int status, enum WAIT_RET *type )
{
    ASSERT_MASTER_THREAD();
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

            if( ::ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)==0 &&
                (siginfo.si_code>>8==PTRACE_EVENT_FORK || siginfo.si_code>>8==PTRACE_EVENT_VFORK ||
                 siginfo.si_code>>8==PTRACE_EVENT_CLONE ) )
            {
                ::ptrace( PTRACE_GETEVENTMSG, pid, NULL, &ret );

                *type=NEWPROCESS;
            } else {
                /* Since we cannot reliably know when PTRACE_O_TRACESYSGOOD is supported, we always assume that's the reason for a
                 * SIGTRACE */
                ret=get_syscall(pid);
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

int reinterpret( enum WAIT_RET prevstate, pid_t pid, int status, long *ret )
{
    // Previous state does not affect us
    // XXX if the first thing the child does is a "fork", is this statement still true?
    abort();
    return prevstate;
}

int get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len )
{
    errno=0;

    size_t offset=((int_ptr)process_ptr)%sizeof(long);
    process_ptr-=offset;
    char *dst=(char *)local_ptr;
    long buffer=ptrace(PTRACE_PEEKDATA, pid, process_ptr, 0);
    if( buffer==-1 && errno!=0 )
        return 0; // false means failure

    while( len>0 ) {
        // XXX Theoretically we can make the write faster by writing it whole "long" at a time. This, of course, requires that
        // the alignment be correct on the receiving side as well as the sending side, which isn't trivial.
        // For the time being, this approach is, at least, system call efficient, so we keep it.
        *dst=((const char *)&buffer)[offset];

        offset++;
        dst++;
        len--;

        if( len>0 && offset==sizeof(long) ) {
            process_ptr+=offset;
            offset=0;

            buffer=ptrace(PTRACE_PEEKDATA, pid, process_ptr, 0);
            if( buffer==-1 && errno!=0 )
                return 0; // false means failure
        }
    }

    return errno==0;
}

int set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len )
{
    long buffer;
    size_t offset=((int_ptr)process_ptr)%sizeof(long);
    process_ptr-=offset; // Make the process PTR aligned

    errno=0;

    if( offset!=0 ) {
        // We have "Stuff" hanging before the area we need to fill - initialize the buffer
        buffer=ptrace( PTRACE_PEEKDATA, pid, process_ptr, 0 );
    }

    const char *src=static_cast<const char *>(local_ptr);

    while( len>0 && errno==0 ) {
        ((char *)&buffer)[offset]=*src;

        src++;
        offset++;
        len--;

        if( offset==sizeof(long) ) {
            ptrace(PTRACE_POKEDATA, pid, process_ptr, buffer);
            process_ptr+=offset;
            offset=0;
        }
    }

    if( errno==0 && offset!=0 ) {
        // We have leftover data we still need to transfer. Need to make sure we are not
        // overwriting data outside of our intended area
        long buffer2=ptrace( PTRACE_PEEKDATA, pid, process_ptr, 0 );

        unsigned int i;
        for( i=offset; i<sizeof(long); ++i )
            ((char *)&buffer)[i]=((char *)&buffer2)[i];

        if( errno==0 )
            ptrace(PTRACE_POKEDATA, pid, process_ptr, buffer);
    }

    return errno==0;
}

int get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen )
{
    /* Are we aligned on the "start" front? */
    unsigned int offset=((unsigned long)process_ptr)%sizeof(long);
    process_ptr-=offset;
    unsigned int i=0;
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

int set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr )
{
    size_t len=strlen(local_ptr)+1;

    return set_mem( pid, local_ptr, process_ptr, len );
}

ssize_t get_cwd( pid_t pid, char *buffer, size_t buff_size )
{
    char tmpbuff[20]; /* Leave enough chars for the digits */
    sprintf(tmpbuff, "/proc/" PID_F "/cwd", pid );

    ssize_t ret=readlink( tmpbuff, buffer, buff_size>0 ? buff_size-1 : 0 );

    if( ret>0 )
        buffer[ret]='\0';

    return ret;
}

ssize_t get_fd( pid_t pid, int fd, char *buffer, size_t buff_size )
{
    char tmpbuff[40];
    sprintf(tmpbuff, "/proc/" PID_F "/fd/%d", pid, fd );

    ssize_t ret=readlink( tmpbuff, buffer, buff_size>0 ? buff_size-1 : 0 );

    if( ret>0 )
        buffer[ret]='\0';

    return ret;
}

pid_t get_parent( pid_t pid )
{
    /* Query the proc filesystem to figure out who the process' parent is */
    char filename[100];
    sprintf(filename, "/proc/" PID_F "/status", pid);

    FILE *stat_file=fopen(filename, "r");
    if( stat_file==NULL ) {
        dlog("%s: Failed to open %s: %s\n", __FUNCTION__, filename, strerror(errno) );

        return -1;
    }

    pid_t ret=-1;

    while( !feof(stat_file) && ret==-1 ) {
        char line[400];
        fgets(line, sizeof(line), stat_file );

        /* If this was not the whole line, consume the rest of it */
        if( line[strlen(line)-1]!='\n' ) {
            int ch;
            while( (ch=getc( stat_file ))!=EOF && ch!='\n' )
                ;
        }

        if( sscanf( line, "PPid: " PID_F, &ret)!=1 )
            ret=-1;
    }

    fclose(stat_file);

    return ret;
}

#if 0
int fork_enter( pid_t pid, int orig_sc, int_ptr process_mem, void *our_mem, void *registers[STATE_SIZE],
        int_ptr context[FORK_CONTEXT_SIZE] )
{
    abort(); // XXX TODO and other tags

    /* Turn the fork/vfork into a clone */
    int clone_flags=CLONE_PTRACE|SIGCHLD;

    if( orig_sc==SYS_vfork ) {
        clone_flags|=CLONE_VFORK|CLONE_VM;
    }

    // Store a copy of the arguments we change, in case they held something important
    int_ptr *save_state=(int_ptr *)registers;
    save_state[0]=get_syscall( pid );
    save_state[1]=get_argument( pid, 1 );
    save_state[2]=get_argument( pid, 2 );

    set_syscall( pid, SYS_clone );
    set_argument( pid, 1, clone_flags ); /* Flags */
    set_argument( pid, 2, 0 ); /* Stack base (keep the same) */

    /* We did change the system call in use */
    return 0;
}

int fork_exit( pid_t pid, pid_t *newpid, void *registers[STATE_SIZE], int_ptr context[FORK_CONTEXT_SIZE] )
{
    int ret=0;

    if( success( pid, SYS_clone ) ) {
        ret=1;
        *newpid=get_retval( pid );
    }

    /* Restore the clobbered registers */
    const int_ptr *save_state=(const int_ptr *)registers;
    set_syscall( pid, save_state[0] );
    set_argument( pid, 1, save_state[1] );
    set_argument( pid, 2, save_state[2] );

    return ret;
}
#endif

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)
{
    ASSERT_SLAVE_THREAD();

    long ret;
    int error;
    thread_proxy.callback( [&](){
            errno=0;
            ret=::ptrace( request, pid, addr, data );
            error=errno;
            });

    errno=error;

    return ret;
}

long ptrace(enum __ptrace_request request, pid_t pid, int_ptr addr, int_ptr signal)
{
    return ptrace( request, pid, (void *)addr, (void *)signal );
}

}; // End of namespace linux
}; // End of namespace ptlib
