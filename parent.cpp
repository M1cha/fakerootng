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

#include <unordered_map>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <wait.h>
#include <unistd.h>
#include <signal.h>

#include "arch/platform.h"
#include "exceptions.h"
#include "worker_queue.h"
#include "daemon.h"

#include "parent.h"

// Static function declarations
static pid_state *lookup_state_create( pid_t pid );

static std::unordered_map<pid_t,std::unique_ptr<pid_state>> children;

// Globally visible sizes of in process memory regions
size_t static_mem_size, shared_mem_size;

// Number of running processes
static int num_processes;

// Signify whether an alarm was received while we were waiting
static bool alarm_happened=false;

class DebuggerThreads : public worker_queue {
private:
    class socketpair {
    private:
        unique_fd m_mainSocket, m_threadSocket;
    public:
        socketpair( int mainSocket, int threadSocket ) :
            m_mainSocket( mainSocket ), m_threadSocket( threadSocket )
        {
            fcntl( m_mainSocket.get(), F_SETFL, O_NONBLOCK );
        }

        int getThreadSocket() const
        {
            return m_threadSocket.get();
        }

        int getMainSocket() const
        {
            return m_mainSocket.get();
        }
    };
    std::mutex m_pthreadRequestSocketsLock;
    std::unordered_map< std::thread::id, socketpair > m_pthreadRequestSockets;
    daemonProcess *m_daemonProcess;
public:
    DebuggerThreads( daemonProcess *daemonProcess ) :
        m_daemonProcess( daemonProcess )
    {}

protected:
    virtual void thread_init();
    virtual void thread_shutdown();
};

thread_local int t_threadSocket = -1;

void DebuggerThreads::thread_init()
{
    int sockets[2];

    // Only the main thread should receive the interesting signals
    sigset_t child_signals;
    sigemptyset( &child_signals );
    sigaddset( &child_signals, SIGCHLD );
    sigaddset( &child_signals, SIGALRM );
    pthread_sigmask( SIG_BLOCK, &child_signals, NULL );

    if( ::socketpair( PF_UNIX, SOCK_SEQPACKET, 0, sockets )<0 )
        throw errno_exception( "Failed to create intra-thread socket pair" );

    m_pthreadRequestSocketsLock.lock();
    auto insertResult = m_pthreadRequestSockets.insert(
            decltype(m_pthreadRequestSockets)::value_type(
                std::this_thread::get_id(), socketpair( sockets[0], sockets[1] )
                )
            );
    m_pthreadRequestSocketsLock.unlock();
    if( ! insertResult.second )
        throw detailed_exception( "Failed to add intra-thread socket pair to hash: already exists" );

    m_daemonProcess->register_thread_socket( insertResult.first->second.getMainSocket() );
    t_threadSocket=insertResult.first->second.getThreadSocket();
}

void DebuggerThreads::thread_shutdown()
{
    m_pthreadRequestSocketsLock.lock();
    auto sockpair = m_pthreadRequestSockets.find( std::this_thread::get_id() );
    m_pthreadRequestSocketsLock.unlock();
    assert( sockpair!=m_pthreadRequestSockets.end() );
    
    m_daemonProcess->unregister_thread_socket( sockpair->second.getMainSocket() );
    m_pthreadRequestSockets.erase( sockpair );
}

static std::unique_ptr<DebuggerThreads> workQ;

struct thread_request {
    enum request_type {
        THREADREQ_PTRACE,
        THREADREQ_PROXYCALL,
    } request;

    union {
        struct {
            __ptrace_request request;
            pid_t pid;
            void *addr;
            void *data;
        } ptrace;
        struct {
            ptlib::thread_callback worker;
            void *opaq;
        } proxy;
    } u;
};

struct result_ptrace {
    long ret;
    int error;
};

struct result_generic {
    int placeholder;
};

class SyscallHandlerTask : public worker_queue::worker_task
{
public:
    SyscallHandlerTask( pid_t pid, pid_state *proc_state, enum ptlib::WAIT_RET ptlib_status, int wait_status,
            long parsed_status ) :
        m_pid( pid ),
        m_proc_state( proc_state ),
        m_ptlib_status( ptlib_status ),
        m_wait_status( wait_status ),
        m_parsed_status( parsed_status )
    {
    }

private:
    pid_t m_pid;
    pid_state *m_proc_state;
    ptlib::WAIT_RET m_ptlib_status;
    int m_wait_status;
    long m_parsed_status;
public:
    virtual void run()
    {
        if( m_proc_state->get_state()==pid_state::INIT || m_proc_state->get_state()==pid_state::NEW_INSTANCE ) {
            if( ! process_initial_signal() )
                return;
        }

        switch( m_ptlib_status ) {
        case ptlib::SIGNAL:
            process_signal();
            break;
        case ptlib::EXIT:
        case ptlib::SIGEXIT:
            process_exit();
            break;
        case ptlib::SYSCALL:
            process_syscall();
            break;
        case ptlib::NEWPROCESS:
            dlog("Should never happen\n");
            dlog(NULL);
            assert(false);
            break;
        }
    }

    static void proxy_call (void *initiator_opaq, ptlib::thread_callback worker_function, void *worker_opaq )
    {
        thread_request req;
        req.request = thread_request::THREADREQ_PROXYCALL;
        req.u.proxy.worker = worker_function;
        req.u.proxy.opaq = worker_opaq;

        ssize_t len = send( t_threadSocket, &req, sizeof(req), 0 );
        if( len<0 )
            throw errno_exception( "Send proxy call to master thread failed" );

        result_generic res;
        len = recv( t_threadSocket, &res, sizeof(res), 0 );

        if( len<0 )
            throw errno_exception( "Recv proxy call from master thread failed" );

        if( static_cast<size_t>(len)<sizeof(res) )
            throw detailed_exception( "Short proxy call response from master thread" );
    }

private:
    bool process_initial_signal()
    {
        if( m_ptlib_status!=ptlib::SIGNAL || m_parsed_status!=SIGSTOP ) {
            dlog("Process " PID_F " reports with something other than SIGSTOP!\n", m_pid);
            assert(false);
            return true;
        }

        dlog("Received initial SIGSTOP on process " PID_F "\n", m_pid);

        if( m_proc_state->get_state()==pid_state::INIT || !ptlib::TRAP_AFTER_EXEC ) {
            // New organic process
            m_proc_state->setStateNone();
            ptrace_continue( 0 );
        } else {
            // New root process
            m_proc_state->setStateNone();
            // Let the fakeroot-ng code run. The process will receive a bogus TRAP after execve
            m_proc_state->wait( []( void *opaq )
                    {
                        SyscallHandlerTask *_this=static_cast<SyscallHandlerTask*>(opaq);
                        SyscallHandlerTask::ptrace( PTRACE_CONT, _this->m_pid, nullptr, nullptr );
                    }, this );
            // The process is not running the client's code - let it run
            ptrace_continue(0);
        }

        return false;
    }

    void process_signal()
    {
        assert( m_ptlib_status==ptlib::SIGNAL );
        dlog("pid " PID_F " received signal %ld\n", m_pid, m_parsed_status);
        ptrace_continue( m_parsed_status );
    }

    void process_syscall()
    {
        dlog("pid " PID_F " system call %ld\n", m_pid, m_parsed_status);
        ptrace_continue( 0 );
    }
    void process_exit()
    {
        // TODO
    }

    void ptrace_continue( int signal )
    {
        if( ptrace( PTRACE_SYSCALL, m_pid, 0, signal )<0 )
            dlog("pid " PID_F " failed to perform ptrace: %s\n", m_pid, strerror(errno));
        // TODO Proper error checking
    }

    static long ptrace( __ptrace_request request, pid_t pid, void *addr, void *data )
    {
        thread_request req;
        req.request = thread_request::THREADREQ_PTRACE;
        req.u.ptrace.request = request;
        req.u.ptrace.pid = pid;
        req.u.ptrace.addr = addr;
        req.u.ptrace.data = data;

        ssize_t len = send( t_threadSocket, &req, sizeof(req), 0 );
        if( len<0 )
            throw errno_exception( "Send ptrace to master thread failed" );

        result_ptrace res;
        len = recv( t_threadSocket, &res, sizeof(res), 0 );

        if( len<0 )
            throw errno_exception( "Recv ptrace from master thread failed" );

        if( static_cast<size_t>(len)<sizeof(res) )
            throw detailed_exception( "Short ptrace response from master thread" );

        errno = res.error;
        return res.ret;
    }

    long ptrace( __ptrace_request request, pid_t pid, void *addr, long signal )
    {
        return ptrace( request, pid, addr, (void *)signal );
    }
};


// Do nothing signal handler for sigchld
static void sigchld_handler(int signum)
{
}

// Signal handler for SIGALARM
static void sigalrm_handler(int signum)
{
    alarm_happened=true;
}


static void handle_new_process( pid_t parent_id, pid_t child_id )
{
    pid_state *child = lookup_state_create( child_id );

    if( parent_id==-1 ) {
        child->setStateNewInstance();
    } else {
        assert( false ); // TODO implement the other case
    }
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

    handle_new_process( -1, child ); // No parent - a root process

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
    shared_mem_size=2*PATH_MAX+ptlib::prepare_memory_len();
    // Round this to the higher page size
    shared_mem_size+=page_size-1;
    shared_mem_size-=shared_mem_size%page_size;
}

pid_state *lookup_state( pid_t pid )
{
    auto retIterator( children.find(pid) );
    
    if( retIterator!=children.end() )
        return retIterator->second.get();
    
    return nullptr;
}

// Lookup a pid. Create the state if not found
static pid_state *lookup_state_create( pid_t pid )
{
    pid_state *ret = lookup_state( pid );
    
    if( ret!=nullptr )
        return ret;

    dlog("Creating state for new child " PID_F "\n", pid);
    ptlib::prepare( pid );

    ret = new pid_state;
    children.insert( std::make_pair( pid, std::unique_ptr<pid_state>( ret ) ) );

    return ret;
}

void init_debugger( daemonProcess *daemonProcess )
{
    // Initialize the ptlib library
    ptlib::init(SyscallHandlerTask::proxy_call, nullptr);

    register_handlers();
    init_globals();

    workQ=std::unique_ptr<DebuggerThreads>( new DebuggerThreads(daemonProcess) );
    workQ->start();
}

void shutdown_debugger()
{
    workQ=nullptr;
}

// ret is the signal (if applicable) or status (if a child exit)
static void process_sigchld( pid_t pid, enum ptlib::WAIT_RET wait_state, int status, long ret )
{
    dlog("%s:%d pid " PID_F " wait_state %d status %08x ret %08lx\n", __FUNCTION__, __LINE__, pid, wait_state, status,
            ret );
    pid_state *proc_state=lookup_state_create(pid);

    switch( proc_state->get_state() ) {
    case pid_state::INIT:
    case pid_state::NEW_INSTANCE:
    case pid_state::NONE:
        workQ->schedule_task( new SyscallHandlerTask( pid, proc_state, wait_state, status, ret ) );
        break;
    case pid_state::KERNEL:
        if( wait_state==ptlib::SYSCALL ) {
            ptrace( PTRACE_SYSCALL, pid, 0, 0 );
            proc_state->setStateNone();
        } else
            workQ->schedule_task( new SyscallHandlerTask( pid, proc_state, wait_state, status, ret ) );
        break;
    case pid_state::WAITING:
        proc_state->wakeup( wait_state, status, ret );
        break;
    case pid_state::WAKEUP:
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
        ptlib::extra_data data;

        enum ptlib::WAIT_RET wait_state;
        if( ptlib::wait( &pid, &status, &data, true ) ) {
            // A child had something to say
            ret=ptlib::parse_wait( pid, status, &wait_state );

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
                dlog( "BUG - ptlib wait failed with %s while numchildren is still %d\n", strerror(errno), num_processes );
                dlog(NULL);
                num_processes=0;
            }
        }
    }

    return 0;
}

static void handle_threadreq_ptrace( int fd, const thread_request *req )
{
    errno=0;
    long res = ptrace( req->u.ptrace.request, req->u.ptrace.pid, req->u.ptrace.addr, req->u.ptrace.data );

    result_ptrace reply = {
        res,
        errno
    };

    if( send( fd, &reply, sizeof(reply), 0 )<0 ) {
        dlog( "Writing to socket %d failed: %s\n", fd, strerror(errno) );
        assert(false);
    }
}

static void handle_threadreq_proxy( int fd, const thread_request *req )
{
    req->u.proxy.worker( req->u.proxy.opaq );

    result_generic reply = { 0 };

    if( send( fd, &reply, sizeof(reply), 0 )<0 ) {
        dlog( "Writing to socket %d failed: %s\n", fd, strerror(errno) );
        assert(false);
    }
}

void handle_thread_request( int fd )
{
    thread_request request;

    ssize_t size = recv( fd, &request, sizeof(request), 0 );
    if( size<0 ) {
        dlog("thread request recv failed on fd %d: %s\n", fd, strerror(errno) );

        return;
    }

    assert( size==sizeof(request) );

    switch( request.request ) {
    case thread_request::THREADREQ_PTRACE:
        handle_threadreq_ptrace( fd, &request );
        break;
    case thread_request::THREADREQ_PROXYCALL:
        handle_threadreq_proxy( fd, &request );
        break;
    default:
        dlog("Unknown thread request %d on fd %d\n", request.request, fd );
    };
}

pid_state::pid_state() :
    m_uid(0), m_euid(0), m_suid(0), m_fsuid(0),
    m_gid(0), m_egid(0), m_sgid(0), m_fsgid(0)
{
}

void pid_state::wait( void (*callback)( void * ), void *opaq )
{
    std::unique_lock<decltype(m_wait_lock)> lock(m_wait_lock);

    state oldstate=m_state;
    m_state=WAITING;

    callback( opaq );

    m_wait_condition.wait( lock, [ this ]{ return m_state==WAKEUP; } );

    m_state=oldstate;
}

void pid_state::wakeup( ptlib::WAIT_RET wait_state, int status, long parsed_status )
{
    std::unique_lock<decltype(m_wait_lock)> lock(m_wait_lock);

    assert( m_state==WAITING );
    m_state=WAKEUP;

    m_wait_state=wait_state;
    m_wait_status=status;
    m_wait_parsed_status=parsed_status;

    m_wait_condition.notify_one();
}
