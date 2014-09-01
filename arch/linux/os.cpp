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

#include <sstream>
#include <unordered_map>
#include <system_error>
#include <mutex>

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

#include "../../log.h"
#include "../platform.h"
#include "os.h"
#include <platform_specific_internal.h>

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

static class {
    callback_initiator m_callback;

public:
    template <typename F>
    void callback( const F &cb_function ) const
    {
        if( std::this_thread::get_id()==ptlib::linux::master_thread )
            cb_function();
        else {
            proxy_function::node<F> node(cb_function);
            m_callback( &node );
        }
    }

    void set_callback( const callback_initiator &cb_init )
    {
        ASSERT( !m_callback );
        m_callback = cb_init;
    }
} thread_proxy;

static std::unordered_map< pid_t, platform::process_state > state_cache;
static std::mutex state_cache_lock;

platform::process_state *get_process_state( pid_t tid, bool create )
{
    std::unique_lock<decltype(state_cache_lock)> lock_guard( state_cache_lock );
    auto i = state_cache.find(tid);
    platform::process_state *ret = &i->second;

    if( i == state_cache.end() ) {
        if( create ) {
            ASSERT_MASTER_THREAD();

            // TODO Should we act to prevent the cache from exploding? Not likely to happen, either way
            ret = &state_cache[tid];
            lock_guard.unlock();

            LOG_T() << "Created cache for process " << tid;
            if( ::ptrace(PTRACE_GETREGS, tid, nullptr, &ret->registers)!=0 )
                throw std::system_error(errno, std::system_category(), "Failed to get registers from process");

            ret->post_load(tid);
        } else {
            ret = nullptr;
        }
    }

    return ret;
}

void init( callback_initiator callback )
{
    thread_proxy.set_callback( callback );
    master_thread = std::this_thread::get_id();
}

void cont( __ptrace_request request, pid_t tid, int signal )
{
    platform::process_state *state = linux::get_process_state(tid, false);

    if( state!=nullptr ) {
        int error;
        thread_proxy.callback([=, &error]() {
                errno=0;
                if( state->dirty ) {
                    LOG_D()<<"Flushing cache for process "<<tid;
                    if( ::ptrace( (__ptrace_request)PTRACE_SETREGS, tid, 0, &state->registers )<0 ) {
                        error = errno;
                        return;
                    }
                }

                LOG_T() << "Deleting cache for process " << tid;
                std::unique_lock< decltype(state_cache_lock) > lock_guard( state_cache_lock );
                state_cache.erase(tid);
                lock_guard.unlock();

                ::ptrace( request, tid, 0, signal );
                error = errno;
            });

        if( error!=0 ) {
            LOG_E() << "Flushing cache failed with error " << strerror(error);
            throw std::system_error(error, std::system_category(), "Failed to flush cache");
        }
    } else {
        LOG_T() << "Process " << tid << " continued with no cache to flush";
        ptrace( request, tid, 0, signal );
    }
}

void prepare( pid_t pid, pid_t tid )
{
    // These cause more harm than good
    //if( ptrace(PTRACE_SETOPTIONS, tid, 0, PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE)!=0 )
    //    perror("PTRACE_SETOPTIONS failed");
}

bool wait( pid_t *tid, int *status, extra_data *data, int async )
{
    ASSERT_MASTER_THREAD();
    *tid=wait4(-1, status, (async?WNOHANG:0)|__WALL, data );

    ASSERT( *tid<=0 || linux::get_process_state(*tid, false)==NULL );

    if( async && *tid==0 ) {
        errno=EAGAIN;
        *tid=-1;
    }

    return *tid!=-1;
}


long parse_wait( pid_t tid, int status, WAIT_RET *type )
{
    ASSERT_MASTER_THREAD();
    long ret;

    if( WIFEXITED(status) ) {
        ret=WEXITSTATUS(status);
        *type=WAIT_RET::EXIT;
    } else if( WIFSIGNALED(status) ) {
        ret=WTERMSIG(status);
        *type=WAIT_RET::SIGEXIT;
    } else if( WIFSTOPPED(status) ) {
        ret=WSTOPSIG(status);

        if( ret==SIGTRAP ) {
            siginfo_t siginfo;

            if( ::ptrace(PTRACE_GETSIGINFO, tid, NULL, &siginfo)==0 &&
                (siginfo.si_code>>8==PTRACE_EVENT_FORK || siginfo.si_code>>8==PTRACE_EVENT_VFORK ||
                 siginfo.si_code>>8==PTRACE_EVENT_CLONE ) )
            {
                ::ptrace( PTRACE_GETEVENTMSG, tid, NULL, &ret );

                *type=WAIT_RET::NEWPROCESS;
            } else {
                /* Since we cannot reliably know when PTRACE_O_TRACESYSGOOD is supported, we always assume that's the reason for a
                 * SIGTRACE */
                ret=get_syscall(tid);
                *type=WAIT_RET::SYSCALL;
            }
        } else {
            LOG_I() << "stopped with some other signal";
            *type=WAIT_RET::SIGNAL;
        }
    } else {
        /* What is going on here? We should never get here. */
        LOG_F() << "Process " << tid << " received unknown status " << HEX_FORMAT(status, 8) << " - aborting";
        abort();
    }

    return ret;
}

WAIT_RET reinterpret( WAIT_RET prevstate, pid_t tid, int status, long *ret )
{
    // Previous state does not affect us
    // XXX if the first thing the child does is a "fork", is this statement still true?
    abort();
    return prevstate;
}

int get_mem( pid_t pid, pid_t tid, int_ptr process_ptr, void *local_ptr, size_t len )
{
    if( std::this_thread::get_id()!=ptlib::linux::master_thread ) {
        int ret;

        thread_proxy.callback( [=,&ret]() { ret = get_mem( pid, tid, process_ptr, local_ptr, len ); } );

        return ret;
    }

    errno=0;

    size_t offset=((int_ptr)process_ptr)%sizeof(long);
    process_ptr-=offset;
    char *dst=(char *)local_ptr;
    long buffer=ptrace(PTRACE_PEEKDATA, tid, process_ptr, 0);
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

            buffer=ptrace(PTRACE_PEEKDATA, tid, process_ptr, 0);
            if( buffer==-1 && errno!=0 )
                return 0; // false means failure
        }
    }

    return errno==0;
}

int set_mem( pid_t pid, pid_t tid, const void *local_ptr, int_ptr process_ptr, size_t len )
{
    if( std::this_thread::get_id()!=ptlib::linux::master_thread ) {
        int ret;

        thread_proxy.callback( [=,&ret]() { ret = set_mem( pid, tid, local_ptr, process_ptr, len ); } );

        return ret;
    }

    long buffer;
    size_t offset=((int_ptr)process_ptr)%sizeof(long);
    process_ptr-=offset; // Make the process PTR aligned

    errno=0;

    if( offset!=0 ) {
        // We have "Stuff" hanging before the area we need to fill - initialize the buffer
        buffer=ptrace( PTRACE_PEEKDATA, tid, process_ptr, 0 );
    }

    const char *src=static_cast<const char *>(local_ptr);

    while( len>0 && errno==0 ) {
        ((char *)&buffer)[offset]=*src;

        src++;
        offset++;
        len--;

        if( offset==sizeof(long) ) {
            ptrace(PTRACE_POKEDATA, tid, process_ptr, buffer);
            process_ptr+=offset;
            offset=0;
        }
    }

    if( errno==0 && offset!=0 ) {
        // We have leftover data we still need to transfer. Need to make sure we are not
        // overwriting data outside of our intended area
        long buffer2=ptrace( PTRACE_PEEKDATA, tid, process_ptr, 0 );

        unsigned int i;
        for( i=offset; i<sizeof(long); ++i )
            ((char *)&buffer)[i]=((char *)&buffer2)[i];

        if( errno==0 )
            ptrace(PTRACE_POKEDATA, tid, process_ptr, buffer);
    }

    return errno==0;
}

int get_string( pid_t pid, pid_t tid, int_ptr process_ptr, char *local_ptr, size_t maxlen )
{
    if( std::this_thread::get_id()!=ptlib::linux::master_thread ) {
        int ret;

        thread_proxy.callback( [=,&ret]() { ret = get_string( pid, tid, process_ptr, local_ptr, maxlen ); } );

        return ret;
    }

    /* Are we aligned on the "start" front? */
    unsigned int offset=((unsigned long)process_ptr)%sizeof(long);
    process_ptr-=offset;
    unsigned int i=0;
    int done=0;
    int word_offset=0;

    while( !done ) {
        unsigned long word=ptrace( PTRACE_PEEKDATA, tid, process_ptr+(word_offset++)*sizeof(long), 0 );

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

int set_string( pid_t pid, pid_t tid, const char *local_ptr, int_ptr process_ptr )
{
    size_t len=strlen(local_ptr)+1;

    return set_mem( pid, tid, local_ptr, process_ptr, len );
}

ssize_t get_cwd( pid_t pid, pid_t tid, char *buffer, size_t buff_size )
{
    std::stringstream formatter;
    formatter << "/proc/" << pid << "/task/" << tid << "/cwd";

    ssize_t ret=readlink( formatter.str().c_str(), buffer, buff_size>0 ? buff_size-1 : 0 );

    if( ret>0 )
        buffer[ret]='\0';

    return ret;
}

ssize_t get_fd( pid_t pid, pid_t tid, int fd, char *buffer, size_t buff_size )
{
    std::stringstream formatter;
    formatter << "/proc/" << pid << "/task/" << tid << "/fd/" << fd;

    ssize_t ret=readlink( formatter.str().c_str(), buffer, buff_size>0 ? buff_size-1 : 0 );

    if( ret>0 )
        buffer[ret]='\0';

    return ret;
}

pid_t get_parent( pid_t pid, pid_t tid )
{
    /* Query the proc filesystem to figure out who the process' parent is */
    std::stringstream filename;
    filename << "/proc/" << pid << "/task/" << tid << "/status";

    // TODO use a better parser (maybe using boost::spirit?)
    FILE *stat_file=fopen(filename.str().c_str(), "r");
    if( stat_file==NULL ) {
        LOG_E() << __FUNCTION__ << ": Failed to open " << filename << ": " << strerror(errno);

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

long ptrace(enum __ptrace_request request, pid_t tid, void *addr, void *data)
{
    long ret;
    int error;
    thread_proxy.callback( [&](){
            errno=0;
            ret=::ptrace( request, tid, addr, data );
            error=errno;
            });

    errno=error;

    if( errno!=0 )
        throw std::system_error(errno, std::system_category(), "ptrace operation failed");

    return ret;
}

long ptrace(enum __ptrace_request request, pid_t tid, int_ptr addr, int_ptr signal)
{
    return ptrace( request, tid, (void *)addr, (void *)signal );
}

}; // End of namespace linux
}; // End of namespace ptlib
