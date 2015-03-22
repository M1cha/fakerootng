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
#include "epoll_event_handlers.h"
#include "proxy_function.h"
#include "lockless_event.h"

#include "syscalls.h"

#include "parent.h"

// Static function declarations

// Keep track of handled syscalls
static std::unordered_map<int, syscall_hook> syscalls;

// Globally visible sizes of in process memory regions
size_t static_mem_size, shared_mem_size;

// Number of running processes
static std::atomic_int num_processes;

// Signify whether an alarm was received while we were waiting
static bool alarm_happened=false;

class proc_state_map {
    std::unordered_map<pid_t,boost::intrusive_ptr<pid_state>> m_processes;
    std::mutex m_lock;

    proc_state_map( const proc_state_map &rhs ) = delete;
    proc_state_map &operator=( const proc_state_map &rhs ) = delete;
public:
    proc_state_map() = default;

    // Lookup a pid. Create the state if not found
    pid_state *lookup( pid_t pid )
    {
        std::lock_guard<std::mutex> guard(m_lock);

        auto retIterator( m_processes.find(pid) );

        if( retIterator!=m_processes.end() )
            return retIterator->second.get();

        LOG_I() << "Creating state for new child " << pid;
        num_processes++;

        pid_state *ret = new pid_state(pid);
        m_processes.insert( std::make_pair( pid, boost::intrusive_ptr<pid_state>( ret ) ) );

        return ret;
    }

    void delete_( pid_t pid )
    {
        std::lock_guard<std::mutex> guard(m_lock);

        m_processes.erase(pid);
    }
} children;

class DebuggerThreads : public worker_queue {
private:
    daemonProcess *m_daemonProcess;
public:
    DebuggerThreads( daemonProcess *daemonProcess ) :
        m_daemonProcess( daemonProcess )
    {}

protected:
    virtual void thread_init();
    virtual void thread_shutdown();
};

void DebuggerThreads::thread_init()
{
    // Only the main thread should receive the interesting signals
    sigset_t child_signals;
    sigemptyset( &child_signals );
    sigaddset( &child_signals, SIGCHLD );
    sigaddset( &child_signals, SIGALRM );
    sigaddset( &child_signals, SIGHUP );
    sigaddset( &child_signals, SIGTERM );
    sigaddset( &child_signals, SIGINT );
    pthread_sigmask( SIG_BLOCK, &child_signals, NULL );
}

void DebuggerThreads::thread_shutdown()
{
}

// Classes for handling task distribution
static std::unique_ptr<DebuggerThreads> workQ;
static proxy_function parent_tasks;
static lockless_event parent_wakeup;

class HandlerTask : public worker_queue::worker_task {
protected:
    HandlerTask( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET ptlib_status, int wait_status,
            long parsed_status ) :
                m_pid( pid ),
                m_proc_state( proc_state ),
                m_ptlib_status( ptlib_status ),
                m_wait_status( wait_status ),
                m_parsed_status( parsed_status )
    {
    }

    pid_t m_pid;
    pid_state *m_proc_state;
    ptlib::WAIT_RET m_ptlib_status;
    int m_wait_status;
    long m_parsed_status;

public:
    static void proxy_call_node ( proxy_function::node_base *node )
    {
        parent_tasks.submit( node );
        parent_wakeup.signal();
        node->wait_done();
    }

    template <typename F>
            static void proxy_call ( const F &function )
    {
        proxy_function::node<F> node( function );
        proxy_call_node(&node);
    }

    void ptrace_kill()
    {
        LOG_E() << "Killing process " << m_pid;
        kill(m_pid, SIGKILL);
        ptlib::cont( PTRACE_SYSCALL, m_pid, SIGKILL );
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

};

class SyscallHandlerTask : public HandlerTask
{
public:
    SyscallHandlerTask( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET ptlib_status, int wait_status,
            long parsed_status, syscall_hook *handler = nullptr ) :
        HandlerTask( pid, proc_state, ptlib_status, wait_status, parsed_status ),
        m_handler_function( handler )
    {
    }

public:
    virtual void run()
    {
        std::unique_lock<std::mutex> state_guard( m_proc_state->lock() );

        ASSERT( m_proc_state->get_state() == pid_state::state::NONE );
        ASSERT( m_ptlib_status == ptlib::WAIT_RET::SYSCALL );

        process_syscall();
    }

private:
    syscall_hook *m_handler_function;

    void process_syscall()
    {
        if( !m_handler_function ) {
            auto handler = syscalls.find(m_parsed_status);
            ASSERT( handler != syscalls.end() );
            m_handler_function = &handler->second;
        }

        m_handler_function->func( m_parsed_status, m_pid, m_proc_state);
    }
};

class SignalHandlerTask : public HandlerTask
{
public:
    SignalHandlerTask( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET ptlib_status, int wait_status,
            long parsed_status ) :
        HandlerTask( pid, proc_state, ptlib_status, wait_status, parsed_status )
    {
    }

    virtual void run()
    {
        std::unique_lock<std::mutex> state_guard( m_proc_state->lock() );

        if( m_proc_state->get_state()==pid_state::state::INIT )
            m_proc_state->wait_initialized(state_guard);

        if( m_proc_state->get_state()==pid_state::state::NEW_ROOT ||
                m_proc_state->get_state()==pid_state::state::NEW_CHILD )
        {
            if( ! process_initial_signal() )
                return;
        }

        LOG_T() << "pid " << m_pid << " received signal " << m_parsed_status;
        ptlib::cont( PTRACE_SYSCALL, m_pid, m_parsed_status );
    }

private:
    bool process_initial_signal()
    {
        if( m_ptlib_status!=ptlib::WAIT_RET::SIGNAL || m_parsed_status!=SIGSTOP ) {
            LOG_W() << "Process " << m_pid << " reports with something other than SIGSTOP!";
            ASSERT(false);
            return true;
        }

        LOG_I() << "Received initial SIGSTOP on process " << m_pid;

        if( m_proc_state->get_state()==pid_state::state::NEW_CHILD || !ptlib::TRAP_AFTER_EXEC ) {
            // New organic process
            m_proc_state->setStateNone();
            ptrace_systrace( 0 );
        } else {
            LOG_D() << "New root process " << m_pid;
            // New root process
            m_proc_state->setStateNone();

            ASSERT(ptlib::TRAP_AFTER_EXEC);
            // Process is still within the fakeroot-ng code. Let it continue.
            // The process will receive a bogus TRAP after execve
            ptrace_continue(0);

            // The process is now running the client's code - let it run and track syscalls
            ptrace_systrace( 0 );
        }

        return false;
    }
};

class ExitHandlerTask : public HandlerTask
{
public:
    ExitHandlerTask( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET ptlib_status, int wait_status,
            long parsed_status ) :
        HandlerTask( pid, proc_state, ptlib_status, wait_status, parsed_status )
    {
    }

    virtual void run()
    {
        std::unique_lock<std::mutex> state_guard( m_proc_state->lock() );

        ASSERT( m_ptlib_status == ptlib::WAIT_RET::EXIT || m_ptlib_status == ptlib::WAIT_RET::SIGEXIT );
        ASSERT( m_proc_state->get_state()==pid_state::state::NONE || m_proc_state->get_state()==pid_state::state::KERNEL );

        LOG_I() << "pid " << m_pid << " exit";
        children.delete_(m_pid);
    }
};

// Do nothing signal handler for sigchld
static void sigchld_handler(int signum)
{
    parent_wakeup.signal_from_sighandler();
}

// Signal handler for SIGALARM
static void sigalrm_handler(int signum)
{
    alarm_happened=true;
}

// Empty handler
static void signop_handler(int signum)
{
}

static void handle_new_process( pid_t child_id )
{
    pid_state *child = children.lookup( child_id );
    std::unique_lock<std::mutex> state_guard( child->lock() );

    child->m_tid = child_id;
    child->setStateNewRoot();
}

pid_state *handle_new_process( pid_t process, pid_t parent, unsigned long flags, pid_state *creator_state )
{
    pid_state *child = children.lookup( process );
    std::unique_lock<std::mutex> state_guard( child->lock() );

    ASSERT(child->get_state() == pid_state::state::INIT);

    child->m_gid = creator_state->m_gid;
    child->m_egid = creator_state->m_egid;
    child->m_sgid = creator_state->m_sgid;
    child->m_fsgid = creator_state->m_fsgid;
    child->m_groups = creator_state->m_groups;

    child->m_uid = creator_state->m_uid;
    child->m_euid = creator_state->m_euid;
    child->m_suid = creator_state->m_suid;
    child->m_fsuid = creator_state->m_fsuid;
    child->m_umask = creator_state->m_umask;

    child->m_ppid = parent;

    if( flags & PROC_FLAGS_THREAD ) {
        child->m_pid = creator_state->m_pid; // New thread - copy process ID from creator
    }

    if( flags & PROC_FLAGS_SAMEVM ) {
        // Point both to same managing struct
        child->m_proc_mem = creator_state->m_proc_mem;
    } else {
        // Parent and child have copies of private buffer at the same address (copy on write)
        child->m_proc_mem->non_shared_addr = creator_state->m_proc_mem->non_shared_addr;
        // Child has a copy of parent's shared memory. We'll release it if and when the child needs its own memory
        // (or when child terminates, of course).
        child->m_proc_mem->shared_addr = creator_state->m_proc_mem->shared_addr;
        // Child does not have a copy of parent's debugger shared memory. This is how we mark to the allocating code
        // that shared_addr needs to be freed.
    }

    child->setStateNewChild();

    return child;
}

bool attach_debugger( pid_t child )
{
    // Attach a debugger to the child
    long ret;
    SyscallHandlerTask::proxy_call( [&ret, child]() {
        ret=ptrace(PTRACE_ATTACH, child, 0, 0);
        if( ret==0 )
            handle_new_process( child );
    } );

    if( ret!=0 ) {
        LOG_E() << "Could not start trace of process " << child << ": " << strerror(errno);

        throw errno_exception( "Could not start trace of process" );
    }
    LOG_I() << "Debugger successfully attached to process " << child;

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
#endif

    // Process
    DEF_SYS1(execve);
#if defined(SYS_fexecve)
    DEF_SYS1(fexecve);
#endif
#if defined(SYS_clone)
    DEF_SYS1(clone);
#endif
    DEF_SYS1(fork);
    DEF_SYS2(vfork, fork);

    // File
    DEF_SYS1(open);
    DEF_SYS1(openat);
    DEF_SYS1(fchownat);
    DEF_SYS2(newfstatat, fstatat);
    DEF_SYS1(stat);
    DEF_SYS2(lstat, stat);
    DEF_SYS2(fstat, stat);
    DEF_SYS1(unlink);
    DEF_SYS2(rmdir, unlink);
    DEF_SYS1(unlinkat);

    // Memory
    DEF_SYS1(munmap);
    DEF_SYS1(mmap);
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

void init_debugger( daemonProcess *daemonProcess )
{
    // Initialize the ptlib library
    ptlib::init( &HandlerTask::proxy_call_node );

    register_handlers();
    init_globals();

    workQ=std::unique_ptr<DebuggerThreads>( new DebuggerThreads(daemonProcess) );
    workQ->start();

    // Prepare the signal masks so we do not lose SIGCHLD while we wait
    struct sigaction action;
    memset( &action, 0, sizeof( action ) );

    action.sa_handler=sigchld_handler;
    sigemptyset( &action.sa_mask );
    action.sa_flags=0;

    sigaction( SIGCHLD, &action, NULL );

    action.sa_handler=sigalrm_handler;
    sigaction( SIGALRM, &action, NULL );

    action.sa_handler=signop_handler;
    sigaction( SIGHUP, &action, NULL );
}

void shutdown_debugger()
{
    workQ=nullptr;
}

static void process_exit( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET wait_state, int status, long ret )
{
    workQ->schedule_task( new ExitHandlerTask( pid, proc_state, wait_state, status, ret ) );
}

static void process_signal( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET wait_state, int status, long signal )
{
    workQ->schedule_task( new SignalHandlerTask( pid, proc_state, wait_state, status, signal ) );
        return;
}

static void process_syscall( pid_t pid, pid_state *proc_state, ptlib::WAIT_RET wait_state, int status, long sc_num )
{
    LOG_T() << "Process " << pid << " in state " << proc_state->get_state();

    switch( proc_state->get_state() ) {
    case pid_state::state::INIT:
        workQ->schedule_task( new SyscallHandlerTask( pid, proc_state, wait_state, status, sc_num ) );
        break;
    case pid_state::state::NONE:
        {
            auto handler = syscalls.find(sc_num);
            if( handler == syscalls.end() ) {
                // No specific handler for this syscall
                LOG_T() << "pid " << pid << " performing unhandled syscall " << sc_num;
                proc_state->setStateKernel();
                ptlib::cont( PTRACE_SYSCALL, pid, 0 );
            } else {
                LOG_T() << "pid " << pid << " performing syscall " << handler->second.name;
                SyscallHandlerTask *task =
                        new SyscallHandlerTask( pid, proc_state, wait_state, status, sc_num, &handler->second );
                proc_state->start_handling( task );
                workQ->schedule_task( task );
            }
        }
        break;
    case pid_state::state::KERNEL:
        ptlib::cont( PTRACE_SYSCALL, pid, 0 );
        proc_state->setStateNone();
        break;
    case pid_state::state::WAITING:
        proc_state->wakeup( wait_state, status, sc_num );
        break;
    case pid_state::state::NEW_ROOT:
    case pid_state::state::NEW_CHILD:
    case pid_state::state::WAKEUP:
        ASSERT(false);
        break;
    }
}

// ret is the signal (if applicable) or status (if a child exit)
static void process_sigchld( pid_t pid, ptlib::WAIT_RET wait_state, int status, long ret )
{
    LOG_T() << "pid " << pid << " wait_state " << wait_state <<
            " status " << HEX_FORMAT(status, 8) << " ret " << HEX_FORMAT(ret, 8);
    pid_state *proc_state=children.lookup(pid);

    switch( wait_state )
    {
    case ptlib::WAIT_RET::EXIT:
    case ptlib::WAIT_RET::SIGEXIT:
        num_processes--;
        process_exit( pid, proc_state, wait_state, status, ret );
        break;
    case ptlib::WAIT_RET::SIGNAL:
        process_signal( pid, proc_state, wait_state, status, ret );
        break;
    case ptlib::WAIT_RET::SYSCALL:
        process_syscall( pid, proc_state, wait_state, status, ret );
        break;
    case ptlib::WAIT_RET::NEWPROCESS:
        ASSERT(false);
        break;
    }
}

int process_children( daemonProcess *daemon )
{
    while(num_processes>0 || daemon->test_should_exit()) {
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
                // Carry out all pending tasks
                proxy_function::node_base *node = parent_tasks.get_job_list();
                while( node!=nullptr ) {
                    node = node->run();
                }
                parent_wakeup.wait();

                // Did an alarm signal arrive?
                if( alarm_happened ) {
                    alarm_happened=false;

                    // TODO implement dump_states();
                }

            } else if( errno==ECHILD ) {
                // We should never get here. If we have no more children, we should have known about it already
                LOG_F() << "BUG - ptlib wait failed with \"" << strerror(errno) << "\" while num_processes is still " <<
                        num_processes;
                num_processes=0;
            }
        }
    }

    return 0;
}

void parent_unconditional_wakeup()
{
    parent_wakeup.signal();
}

pid_state::pid_state(pid_t pid) :
    m_uid(0), m_euid(0), m_suid(0), m_fsuid(0),
    m_gid(0), m_egid(0), m_sgid(0), m_fsgid(0),
    m_umask(0), m_pid(pid), m_tid(pid), m_ppid(0), m_flags(0)
{
}

template<class CALLBACK>
void pid_state::wait( const CALLBACK &callback )
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

    ASSERT( m_state==state::WAITING );
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
    ASSERT( m_task==nullptr );
    m_task = task;
}

void pid_state::terminate()
{
    SyscallHandlerTask::proxy_call( [this]()
            {
                m_task->ptrace_kill();
                m_state=state::NONE;
                m_task=nullptr;
            } );
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

std::unique_lock<std::mutex> pid_state::uses_buffers()
{
    // Not easy to allocate buffers after we've already created a thread.
    ASSERT( m_pid == m_tid );

    std::unique_lock<std::mutex> guard(m_proc_mem->lock);
    if( m_proc_mem->shared_ptr )
        return guard; // Process already has memory

    ptlib::cpu_state saved_state = ptlib::save_state( m_tid );

    if( !m_proc_mem->non_shared_addr ) {
        // Allocate the private use area
        m_proc_mem->non_shared_addr = proxy_mmap( "Mmap private storage in debugee process failed", m_pid,
                                                  0, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC,
                                                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0 );
        LOG_D() << "Mapped private memory pid "<<m_pid<<" address 0x"<<HEX_FORMAT(m_proc_mem->non_shared_addr, 0);
    } else {
        // Already has private area, but has someone else's shared area mapped
        proxy_munmap( "Munmapping stale shared mem in debugee process failed", m_pid,
                      m_proc_mem->shared_addr - ptlib::prepare_memory_len, shared_mem_size );

        LOG_D() << "Unmapped stale shared memory pid "<<m_pid<<" address 0x"<<
                HEX_FORMAT(m_proc_mem->shared_addr - ptlib::prepare_memory_len, 0);

        m_proc_mem->shared_addr = 0;
    }

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
    m_proc_mem->shared_ptr = unique_mmap("Failed to mmap shared mem file", fd.get(), shared_mem_size, 0,
                PROT_READ|PROT_WRITE, MAP_SHARED);
    LOG_D() << "Mapped shared memory pid "<<m_pid<<" to local address "<<m_proc_mem->shared_ptr.get<void>();

    // Fill in the memory with necessary commands
    memcpy( m_proc_mem->shared_ptr.get<void>(), ptlib::prepare_memory(), ptlib::prepare_memory_len );

    // The local shared memory is mapped. Now we need to map the remote end
    // Generate a new system call
    // Copy the instructions for generating a syscall to the newly created memory
    ptlib::set_mem( m_pid, m_tid, ptlib::prepare_memory(), m_proc_mem->non_shared_addr, ptlib::prepare_memory_len );

    // Our generate_syscall function looks for the instructions in the shared memory member. This has not, yet, been
    // mapped in the debugee. Fool it to use the static buffer instead, for now.
    m_proc_mem->shared_addr = m_proc_mem->non_shared_addr + ptlib::prepare_memory_len;

    generate_syscall( m_tid );
    ptrace_syscall_wait( m_tid, 0 );

    // Open the same file by the debugee
    ptlib::set_string( m_pid, m_tid, filename, m_proc_mem->non_shared_addr+ptlib::prepare_memory_len );
    int remote_fd = proxy_open( "Opening shared memory file failed in debugee", m_tid,
            m_proc_mem->non_shared_addr+ptlib::prepare_memory_len, O_RDONLY );

    // MMap it
    generate_syscall( m_tid );
    ptrace_syscall_wait( m_tid, 0 );

    m_proc_mem->shared_addr = proxy_mmap( "Mapping shared memory file failed in debugee", m_tid,
            0, shared_mem_size, PROT_READ|PROT_EXEC, MAP_SHARED, remote_fd, 0 ) + ptlib::prepare_memory_len;
    LOG_D() << "Mapped shared memory pid "<<m_pid<<" address 0x"<<
            HEX_FORMAT(m_proc_mem->shared_addr - ptlib::prepare_memory_len, 0);

    // Close the file descriptor
    generate_syscall( m_tid );
    ptrace_syscall_wait( m_tid, 0 );

    proxy_close( "Closing shared memory file failed in debugee. How is this even possible?", m_tid, remote_fd );

    // Function was entered just entering a system call. Return to the same state before restoring the state
    generate_syscall( m_tid );
    ptrace_syscall_wait( m_tid, 0 );

    ptlib::restore_state( m_tid, &saved_state );

    return guard;
}

void pid_state::verify_syscall_success( pid_t pid, int sc_num, const char *exception_message ) const
{
    if( !ptlib::success( pid, sc_num ) )
        throw std::system_error( ptlib::get_error( pid, sc_num ), std::system_category(),
                exception_message );
}

void pid_state::generate_syscall( pid_t pid ) const
{
    ptlib::generate_syscall( pid, m_proc_mem->shared_addr );
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

void pid_state::proxy_munmap(const char *exception_message, pid_t pid,
                int_ptr addr, size_t length)
{
    ptlib::set_syscall( pid, ptlib::preferred::MUNMAP );
    ptlib::set_argument( pid, 1, addr );
    ptlib::set_argument( pid, 2, length );

    ptrace_syscall_wait( pid, 0 );

    // Check mmap's return value
    verify_syscall_success( pid, ptlib::preferred::MUNMAP, exception_message );
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
