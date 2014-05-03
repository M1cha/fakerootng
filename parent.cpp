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
#include "log.h"
#include "scope_guard.h"

#include "syscalls.h"

#include "parent.h"

// Static function declarations
static pid_state *lookup_state_create( pid_t pid );

static std::unordered_map<pid_t,std::unique_ptr<pid_state>> children;

// Keep track of handled syscalls
static std::unordered_map<int, syscall_hook> syscalls;

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
            const std::function< void() > *worker;
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
    SyscallHandlerTask( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET ptlib_status, int wait_status,
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
        if( m_proc_state->get_state()==pid_state::state::INIT || m_proc_state->get_state()==pid_state::state::NEW ) {
            if( ! process_initial_signal() )
                return;
        }

        switch( m_ptlib_status ) {
        case ptlib::WAIT_RET::SIGNAL:
            process_signal();
            break;
        case ptlib::WAIT_RET::EXIT:
        case ptlib::WAIT_RET::SIGEXIT:
            LOG_F() << "BUG - EXIT and SIGEXIT were meant to be handled by the master thread";
            assert(false);
            break;
        case ptlib::WAIT_RET::SYSCALL:
            process_syscall();
            break;
        case ptlib::WAIT_RET::NEWPROCESS:
            LOG_F() << "Should never happen";
            assert(false);
            break;
        }
    }

    static void proxy_call ( const std::function< void() > &worker_function )
    {
        thread_request req;
        req.request = thread_request::THREADREQ_PROXYCALL;
        req.u.proxy.worker = &worker_function;

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

    void ptrace_systrace( int signal )
    {
        ptlib::cont( PTRACE_SYSCALL, m_pid, 0 );
    }

    void ptrace_continue( int signal )
    {
        m_proc_state->wait( [this]()
                {
                    ptlib::cont( PTRACE_CONT, m_pid, 0 );
                    //SyscallHandlerTask::ptrace( PTRACE_CONT, m_pid, nullptr, nullptr );
                } );
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

    static long ptrace( __ptrace_request request, pid_t pid, void *addr, long signal )
    {
        return ptrace( request, pid, addr, (void *)signal );
    }

private:
    bool process_initial_signal()
    {
        if( m_ptlib_status!=ptlib::WAIT_RET::SIGNAL || m_parsed_status!=SIGSTOP ) {
            LOG_W() << "Process " << m_pid << " reports with something other than SIGSTOP!";
            assert(false);
            return true;
        }

        LOG_I() << "Received initial SIGSTOP on process " << m_pid;

        if( m_proc_state->get_state()==pid_state::state::INIT || !ptlib::TRAP_AFTER_EXEC ) {
            // New organic process
            m_proc_state->setStateNone();
            ptrace_systrace( 0 );
        } else {
            LOG_D() << "New root process " << m_pid;
            // New root process
            m_proc_state->setStateNone();

            assert(ptlib::TRAP_AFTER_EXEC);
            // Process is still within the fakeroot-ng code. Let it continue.
            // The process will receive a bogus TRAP after execve
            ptrace_continue(0);

            // The process is now running the client's code - let it run and track syscalls
            ptlib::cont( PTRACE_SYSCALL, m_pid, 0 );
        }

        return false;
    }

    void process_signal()
    {
        assert( m_ptlib_status==ptlib::WAIT_RET::SIGNAL );
        LOG_T() << "pid " << m_pid << " received signal " << m_parsed_status;
        ptrace_systrace( m_parsed_status );
    }

    void process_syscall()
    {
        auto handler = syscalls.find(m_parsed_status);
        if( handler == syscalls.end() ) {
            // No specific handler for this syscall
            LOG_T() << "pid " << m_pid << " system call " << m_parsed_status;
            m_proc_state->setStateKernel();
            ptrace_systrace( 0 );
        } else {
            LOG_T() << "pid " << m_pid << " system call " << handler->second.name;
            m_proc_state->start_handling( this );
            handler->second.func( m_parsed_status, m_pid, m_proc_state);
        }
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
    flush_log();

    // Attach a debugger to the child
    if( ptrace(PTRACE_ATTACH, child, 0, 0)!=0 ) {
        LOG_E() << "Could not start trace of process " << child << ": " << strerror(errno);

        throw errno_exception( "Could not start trace of process" );
    }
    LOG_I() << "Debugger successfully attached to process " << child;

    handle_new_process( -1, child ); // No parent - a root process

    return true;
}

static void register_handlers()
{
    // A macro for defining a system call with different syscall and handler names
#define DEF_SYS2( syscall, function ) syscalls[SYS_##syscall]=syscall_hook(sys_##function, #syscall)
    // A macro for defining a system call with the same syscall and handler names
#define DEF_SYS1( syscall ) DEF_SYS2( syscall, syscall )

    // Credentials
    DEF_SYS1(getuid);
    DEF_SYS1(geteuid);
    DEF_SYS1(getresuid);
#if defined(SYS_getuid16)
    DEF_SYS2(getuid16, getuid);

    // Process
#endif
    DEF_SYS1(execve);
#if defined(SYS_fexecve)
    DEF_SYS1(fexecve);
#endif
#if defined(SYS_clone)
    DEF_SYS1(clone);
#endif

    // File
    DEF_SYS1(fchownat);
    DEF_SYS2(newfstatat, fstatat);
    DEF_SYS1(stat);
    DEF_SYS2(lstat, stat);
    DEF_SYS2(fstat, stat);
}

void init_globals()
{
    size_t page_size=sysconf(_SC_PAGESIZE);

    static_mem_size=page_size;
    shared_mem_size=2*PATH_MAX+ptlib::prepare_memory_len;
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

    LOG_I() << "Creating state for new child " << pid;
    num_processes++;
    ptlib::prepare( pid );

    ret = new pid_state;
    children.insert( std::make_pair( pid, std::unique_ptr<pid_state>( ret ) ) );

    return ret;
}

void init_debugger( daemonProcess *daemonProcess )
{
    // Initialize the ptlib library
    ptlib::init(SyscallHandlerTask::proxy_call);

    register_handlers();
    init_globals();

    workQ=std::unique_ptr<DebuggerThreads>( new DebuggerThreads(daemonProcess) );
    workQ->start();
}

void shutdown_debugger()
{
    workQ=nullptr;
}

static void process_exit( pid_t pid, ptlib::WAIT_RET wait_state, int status, long ret )
{
    num_processes--;
    LOG_I() << "pid " << pid << " exit";
}

static void process_syscall( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET wait_state, int status, long ret )
{
    workQ->schedule_task( new SyscallHandlerTask( pid, proc_state, wait_state, status, ret ) );
}

// ret is the signal (if applicable) or status (if a child exit)
static void process_sigchld( pid_t pid, ptlib::WAIT_RET wait_state, int status, long ret )
{
    LOG_T() << "pid " << pid << " wait_state " << wait_state <<
            " status " << HEX_FORMAT(status, 8) << " ret " << HEX_FORMAT(ret, 8);
    pid_state *proc_state=lookup_state_create(pid);

    // Handle process exits synchronously
    if( wait_state==ptlib::WAIT_RET::EXIT || wait_state==ptlib::WAIT_RET::SIGEXIT ) {
        process_exit( pid, wait_state, status, ret );

        return;
    }

    LOG_T() << "Process " << pid << " in state " << proc_state->get_state();
    switch( proc_state->get_state() ) {
    case pid_state::state::INIT:
    case pid_state::state::NEW:
    case pid_state::state::NONE:
        process_syscall( pid, proc_state, wait_state, status, ret );
        break;
    case pid_state::state::KERNEL:
        if( wait_state==ptlib::WAIT_RET::SYSCALL ) {
            ptlib::cont( PTRACE_SYSCALL, pid, 0 );
            proc_state->setStateNone();
        } else
            workQ->schedule_task( new SyscallHandlerTask( pid, proc_state, wait_state, status, ret ) );
        break;
    case pid_state::state::WAITING:
        proc_state->wakeup( wait_state, status, ret );
        break;
    case pid_state::state::WAKEUP:
        assert(false);
        break;
    }
}

int process_children( daemonProcess *daemon )
{
    LOG_I() << "Begin the process loop";

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

        ptlib::WAIT_RET wait_state;
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
                LOG_F() << "BUG - ptlib wait failed with " << strerror(errno) << " while numchildren is still " <<
                        num_processes;
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
        LOG_F() << "Writing to socket " << fd << " failed: " << strerror(errno);
        assert(false);
    }
}

static void handle_threadreq_proxy( int fd, const thread_request *req )
{
    (*req->u.proxy.worker)();

    result_generic reply = { 0 };

    if( send( fd, &reply, sizeof(reply), 0 )<0 ) {
        LOG_F() << "Writing to socket " << fd << " failed: " << strerror(errno);
        assert(false);
    }
}

void handle_thread_request( int fd )
{
    thread_request request;

    ssize_t size = recv( fd, &request, sizeof(request), 0 );
    if( size<0 ) {
        LOG_E() << "thread request recv failed on fd " << fd << ": " << strerror(errno);

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
        LOG_E() << "Unknown thread request " << request.request << " on fd " << fd;
        break;
    };
}

pid_state::pid_state() :
    m_uid(0), m_euid(0), m_suid(0), m_fsuid(0),
    m_gid(0), m_egid(0), m_sgid(0), m_fsgid(0)
{
}

void pid_state::wait( const std::function< void ()> &callback )
{
    std::unique_lock<decltype(m_wait_lock)> lock(m_wait_lock);

    state oldstate=m_state;
    m_state=state::WAITING;

    lock.unlock();
    callback();
    lock.lock();

    m_wait_condition.wait( lock, [ this ]{ return m_state==state::WAKEUP; } );

    m_state=oldstate;
    LOG_T()<<"Setting state back to "<<m_state;
}

void pid_state::wakeup( ptlib::WAIT_RET wait_state, int status, long parsed_status )
{
    std::unique_lock<decltype(m_wait_lock)> lock(m_wait_lock);

    assert( m_state==state::WAITING );
    m_state=state::WAKEUP;

    m_wait_state=wait_state;
    m_wait_status=status;
    m_wait_parsed_status=parsed_status;

    m_wait_condition.notify_one();
}

void pid_state::ptrace_syscall_wait( pid_t pid, int signal )
{
    wait( [&]()
            {
                ptlib::cont( PTRACE_SYSCALL, pid, signal );
            } );
}

void pid_state::start_handling( SyscallHandlerTask *task )
{
    assert( m_task==nullptr );
    m_task = task;
}

void pid_state::end_handling()
{
    SyscallHandlerTask::proxy_call( [this]()
            {
                m_task->ptrace_systrace(0);
                m_state=state::NONE;
                m_task=nullptr;
            } );
}

void pid_state::uses_buffers( pid_t pid )
{
    if( m_proc_mem.shared_addr != 0 )
        return; // Process already has memory

    ptlib::cpu_state saved_state = ptlib::save_state( pid );

    // Allocate the private use area
    m_proc_mem.non_shared_addr = proxy_mmap( "Mmap private storage in debugee process failed", pid,
            0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );

    char filename[PAGE_SIZE - ptlib::prepare_memory_len];
    const char *tmpdir=getenv("FAKEROOT_TMPDIR");

    if( tmpdir==NULL )
        tmpdir=getenv("TMPDIR");

    if( tmpdir==NULL || strlen(tmpdir)>=sizeof(filename)-sizeof("/fakeroot-ng.XXXXXX") )
        tmpdir=DEFAULT_TMPDIR;

    int neededSize = snprintf(filename, sizeof(filename), "%s/fakeroot-ng.XXXXXX", tmpdir);
    if( neededSize<0 )
        throw std::system_error( errno, std::system_category(), "Formatting temporary path failed" );
    if( size_t(neededSize) >= sizeof(filename) )
        throw std::out_of_range( "Fakeroot temporary path too long" );

    unique_fd fd( mkstemp(filename), "Failed to create shared mem file" );
    auto rmfile_scope = makeScopeGuard([filename]() {unlink(filename);});

    // Make sure that the file is big enough, but create it sparse
    ftruncate( fd.get(), shared_mem_size );

    // Map the file into the local address space
    m_proc_mem.shared_ptr = unique_mmap("Failed to mmap shared mem file", fd.get(), shared_mem_size, 0,
                PROT_READ|PROT_WRITE, MAP_SHARED);

    // Fill in the memory with necessary commands
    memcpy( m_proc_mem.shared_ptr.get<void>(), ptlib::prepare_memory(), ptlib::prepare_memory_len );

    // The local shared memory is mapped. Now we need to map the remote end
    // Generate a new system call
    // Copy the instructions for generating a syscall to the newly created memory
    ptlib::set_mem( pid, ptlib::prepare_memory(), m_proc_mem.non_shared_addr, ptlib::prepare_memory_len );

    // Our generate_syscall function looks for the instructions in the shared memory member. This has not, yet, been
    // mapped in the debugee. Fool it to use the static buffer instead, for now.
    m_proc_mem.shared_addr = m_proc_mem.non_shared_addr + ptlib::prepare_memory_len;

    generate_syscall( pid );
    ptrace_syscall_wait( pid, 0 );

    // Open the same file by the debugee
    ptlib::set_string( pid, filename, m_proc_mem.non_shared_addr+ptlib::prepare_memory_len );
    int remote_fd = proxy_open( "Opening shared memory file failed in debugee", pid,
            m_proc_mem.non_shared_addr+ptlib::prepare_memory_len, O_RDONLY );

    // MMap it
    generate_syscall( pid );
    ptrace_syscall_wait( pid, 0 );

    m_proc_mem.shared_addr = proxy_mmap( "Mapping shared memory file failed in debugee", pid,
            0, shared_mem_size, PROT_READ|PROT_EXEC, MAP_SHARED, remote_fd, 0 ) + ptlib::prepare_memory_len;

    // Close the file descriptor
    generate_syscall( pid );
    ptrace_syscall_wait( pid, 0 );

    proxy_close( "Closing shared memory file failed in debugee. How is this even possible?", pid, remote_fd );

    // Function was entered just entering a system call. Return to the same state before restoring the state
    generate_syscall( pid );
    ptrace_syscall_wait( pid, 0 );

    ptlib::restore_state( pid, &saved_state );
}

void pid_state::verify_syscall_success( pid_t pid, int sc_num, const char *exception_message ) const
{
    if( !ptlib::success( pid, sc_num ) )
        throw std::system_error( ptlib::get_error( pid, sc_num ), std::system_category(),
                exception_message );
}

void pid_state::generate_syscall( pid_t pid ) const
{
    ptlib::generate_syscall( pid, m_proc_mem.shared_addr );
}

int_ptr pid_state::proxy_mmap(const char *exception_message, pid_t pid,
                int_ptr addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    ptlib::set_syscall( pid, ptlib::preferred::MMAP );
    ptlib::set_argument( pid, 1, addr );
    ptlib::set_argument( pid, 2, length );
    ptlib::set_argument( pid, 3, prot );
    ptlib::set_argument( pid, 4, flags );
    ptlib::set_argument( pid, 5, fd );
    ptlib::set_argument( pid, 6, offset );

    ptrace_syscall_wait( pid, 0 );

    // Check mmap's return value
    verify_syscall_success( pid, ptlib::preferred::MMAP, exception_message );

    return ptlib::get_retval( pid );
}

int pid_state::proxy_open(const char *exception_message, pid_t pid,
        int_ptr pathname, int flags, mode_t mode)
{
    ptlib::set_syscall( pid, ptlib::preferred::OPEN );
    ptlib::set_argument( pid, 1, pathname );
    ptlib::set_argument( pid, 2, flags );
    ptlib::set_argument( pid, 3, mode );
    ptrace_syscall_wait( pid, 0 );

    // Test to see if the open was successful
    verify_syscall_success( pid, ptlib::preferred::OPEN, exception_message );

    return ptlib::get_retval( pid );
}
void pid_state::proxy_close(const char *exception_message, pid_t pid,
        int fd)
{
    ptlib::set_syscall( pid, ptlib::preferred::CLOSE );
    ptlib::set_argument( pid, 1, fd );
    ptrace_syscall_wait( pid, 0 );

    verify_syscall_success( pid, ptlib::preferred::OPEN, exception_message );
}
