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

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <wait.h>
#include <unistd.h>
#include <signal.h>

#include "arch/platform.h"
#include "exceptions.h"
#include "worker_queue.h"
#include "daemon.h"

#include "parent.h"

class NewProcessTask : public SyscallHandlerTask
{
public:
    // XXX Constructor inheritence would make more sense here, but these are only supported starting with gcc 4.8
    NewProcessTask(pid_t pid, pid_state *proc_state, enum PTLIB_WAIT_RET ptlib_status, int wait_status,
            long parsed_status ) :
        SyscallHandlerTask( pid, proc_state, ptlib_status, wait_status, parsed_status )
    {
    }

    void run()
    {
    }
};

class GenericSyscallTask : public SyscallHandlerTask
{
public:
    // XXX Constructor inheritence would make more sense here, but these are only supported starting with gcc 4.8
    GenericSyscallTask(pid_t pid, pid_state *proc_state, enum PTLIB_WAIT_RET ptlib_status, int wait_status,
            long parsed_status ) :
        SyscallHandlerTask( pid, proc_state, ptlib_status, wait_status, parsed_status )
    {
    }

    void run()
    {
    }
};

// Globally visible sizes of in process memory regions
size_t static_mem_size, shared_mem_size;

// Number of running processes
static int num_processes;

// Signify whether an alarm was received while we were waiting
static bool alarm_happened=false;

static std::unique_ptr<worker_queue> workQ;

// Do nothing signal handler for sigchld
static void sigchld_handler(int signum)
{
}

// Signal handler for SIGALARM
static void sigalrm_handler(int signum)
{
    alarm_happened=true;
}


bool attach_debugger( pid_t child )
{
    dlog(NULL);

    // Attach a debugger to the child
    if( ptrace(PTRACE_ATTACH, child, 0, 0)!=0 ) {
        dlog("Could not start trace of process " PID_F ": %s\n", child, strerror(errno) );

        throw errno_exception( "Could not start trace of process" );
    }
    dlog("Debugger successfully attached to process " PID_F "\n", child );

    // TODO handle_new_process( -1, child ); // No parent - a root process

    return true;
}

static void register_handlers()
{
    // TODO implement
}

void init_globals()
{
    size_t page_size=sysconf(_SC_PAGESIZE);

    static_mem_size=page_size;
    shared_mem_size=2*PATH_MAX+ptlib_prepare_memory_len();
    // Round this to the higher page size
    shared_mem_size+=page_size-1;
    shared_mem_size-=shared_mem_size%page_size;
}

// Lookup a pid. Create the state if not found
pid_state *lookup_state_create( pid_t pid )
{
    // TODO implement
}

void init_debugger()
{
    // Initialize the ptlib library
    ptlib_init();

    register_handlers();
    init_globals();

    workQ=std::unique_ptr<worker_queue>( new worker_queue() );
}

void shutdown_debugger()
{
    workQ=nullptr;
}

static void process_syscall( pid_t pid, pid_state *proc_state, enum PTLIB_WAIT_RET wait_state, int status, long ret )
{
    workQ->schedule_task( new GenericSyscallTask( pid, proc_state, wait_state, status, ret ) );
}

static void process_signal( pid_t pid, pid_state *proc_state, enum PTLIB_WAIT_RET wait_state, int status, long ret )
{
}

static void process_exit( pid_t pid, pid_state *proc_state, enum PTLIB_WAIT_RET wait_state, int status, long ret )
{
}

// ret is the signal (if applicable) or status (if a child exit)
static void process_sigchld( pid_t pid, enum PTLIB_WAIT_RET wait_state, int status, long ret )
{
    pid_state *proc_state=lookup_state_create(pid);

    if( proc_state->get_state()==pid_state::INIT )
        workQ->schedule_task( new NewProcessTask( pid, proc_state, wait_state, status, ret ) );

    switch( wait_state ) {
    case SIGNAL:
        process_signal( pid, proc_state, wait_state, status, ret );
        break;
    case EXIT:
    case SIGEXIT:
        process_exit( pid, proc_state, wait_state, status, ret );
        break;
    case SYSCALL:
        process_syscall( pid, proc_state, wait_state, status, ret );
        break;
    case NEWPROCESS:
        dlog("Should never happen\n");
        dlog(NULL);
        assert(false);
        break;
    }
}

int process_children( daemonProcess *daemon )
{
    dlog( "Begin the process loop\n" );

    // Prepare the signal masks so we do not lose SIGCHLD while we wait

    struct sigaction action;
    memset( &action, 0, sizeof( action ) );

    action.sa_handler=sigchld_handler;
    sigemptyset( &action.sa_mask );
    action.sa_flags=0;

    sigaction( SIGCHLD, &action, NULL );

    action.sa_handler=sigalrm_handler;
    sigaction( SIGALRM, &action, NULL );

    sigset_t orig_signals, child_signals;

    sigemptyset( &child_signals );
    sigaddset( &child_signals, SIGCHLD );
    sigaddset( &child_signals, SIGALRM );
    sigprocmask( SIG_BLOCK, &child_signals, &orig_signals );

    sigdelset( &orig_signals, SIGCHLD );
    sigdelset( &orig_signals, SIGALRM );

    bool clientsockets=true;

    while(num_processes>0 || clientsockets) {
        int status;
        pid_t pid;
        long ret;
        ptlib_extra_data data;

        enum PTLIB_WAIT_RET wait_state;
        if( ptlib_wait( &pid, &status, &data, true ) ) {
            // A child had something to say
            ret=ptlib_parse_wait( pid, status, &wait_state );

            process_sigchld( pid, wait_state, status, ret );
        } else {
            if( errno==EAGAIN || (errno==ECHILD && num_processes==0) ) {
                clientsockets=daemon->handle_request( &orig_signals, num_processes>0 );

                // Did an alarm signal arrive?
                if( alarm_happened ) {
                    alarm_happened=false;

                    // TODO implement dump_states();
                }

            } else if( errno==ECHILD ) {
                // We should never get here. If we have no more children, we should have known about it already
                dlog( "BUG - ptlib_wait failed with %s while numchildren is still %d\n", strerror(errno), num_processes );
                dlog(NULL);
                num_processes=0;
            }
        }
    }

    return 0;
}
