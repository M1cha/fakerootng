#ifndef PARENT_H
#define PARENT_H

#include <set>
#include <memory>

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <sys/types.h>
#include <assert.h>

#include <semaphore.h>

#include "arch/platform.h"
#include "worker_queue.h"

#include "unique_mmap.h"
#include "log.h"

class daemonProcess;
class pid_state;
class SyscallHandlerTask;

// We know of a new process in the system
pid_state *handle_new_process( pid_t process, pid_t parent, unsigned long flags, pid_state *creator_state );
// Attach the debugger to a specific child
bool attach_debugger( pid_t child );
// Initialize the debugger environment
void init_debugger( daemonProcess *daemonProcess );
// Shutdown the debugger environment
void shutdown_debugger();
// Main processing loop
int process_children( daemonProcess *daemon );
// Wake up the parent thread without submitting any particular job
void parent_unconditional_wakeup();

// handle_new_process flags
static const unsigned long PROC_FLAGS_SAMEVM = 1,
        PROC_FLAGS_CUSTOM_NOTIFY_PARENT = 2,
        PROC_FLAGS_THREAD = 4;

class pid_state : public boost::intrusive_ref_counter<pid_state>
{
public:
    enum class state {
        INIT,       ///< Sanity - process should never actually do anything while in this state
        NEW_ROOT,   ///< New process, recently registered. Should see a SIGSTOP next
        NEW_CHILD,  ///< New child process/thread. Should see SIGSTOP next
        NONE,       ///< Idle state
        KERNEL,     ///< Inside a system call
        WAITING,    ///< A worker thread is waiting on this process
        WAKEUP,     ///< Process is in the process of waking up waiter
    };
    
    // The credentials (including the Linux specific file system UID)
    uid_t m_uid, m_euid, m_suid, m_fsuid;
    gid_t m_gid, m_egid, m_sgid, m_fsgid;
    std::set<gid_t> m_groups;

    pid_t m_pid, m_tid, m_ppid;

    struct process_memory {
        // TODO add locking
        int_ptr non_shared_addr = 0;
        int_ptr shared_addr = 0;
        unique_mmap shared_ptr;

        process_memory() = default;
        process_memory(const process_memory &rhs) :
            non_shared_addr(rhs.non_shared_addr),
            shared_addr(rhs.shared_addr)
        // Use uninitialized shared_ptr to indicate this is a copy
        {
        }

        process_memory &operator=( const process_memory &rhs ) = delete;

        template <typename T> T* get_shared_addr()
        {
            return reinterpret_cast<T*>(shared_ptr.get<char>() + ptlib::prepare_memory_len);
        }
    };
    std::shared_ptr<process_memory> m_proc_mem{ new process_memory };
private:
    enum state m_state = state::INIT;
    SyscallHandlerTask *m_task = nullptr;
    std::mutex m_state_lock;
    std::mutex m_wait_lock;
    std::condition_variable m_wait_condition;
    ptlib::WAIT_RET m_wait_state = ptlib::WAIT_RET::NEWPROCESS;
    int m_wait_status = 0;
    long m_wait_parsed_status = 0;

    unsigned long m_flags;
    boost::intrusive_ptr<const pid_state> m_process_leader;

public:
    explicit pid_state(pid_t pid);

    std::unique_lock<std::mutex> lock()
    {
        return std::unique_lock<std::mutex>( m_state_lock );
    }

    void wait_initialized(std::unique_lock<std::mutex> &lock)
    {
    	ASSERT(m_state==state::INIT);
    	m_wait_condition.wait(lock, [this]() { return m_state != state::INIT; });
    }

    enum state get_state() const
    {
        return m_state;
    }

    void setStateNone()
    {
    	state oldstate = m_state;

        m_state=state::NONE;

    	if( oldstate==state::INIT ) {
    		m_wait_condition.notify_all();
    	}
    }

    void setStateNewRoot()
    {
        ASSERT(m_state==state::INIT);
        m_state=state::NEW_ROOT;

        ptlib::prepare( m_pid, m_tid );
        m_wait_condition.notify_all();
    }

    void setStateNewChild()
    {
        ASSERT(m_state==state::INIT);
        m_state=state::NEW_CHILD;

        ptlib::prepare( m_pid, m_tid );
        m_wait_condition.notify_all();
    }

    void setStateKernel()
    {
        ASSERT(m_state==state::NONE);
        m_state=state::KERNEL;
    }

    void wait( const std::function< void ()> &callback );
    void wakeup( ptlib::WAIT_RET wait_state, int status, long parsed_status );
    void ptrace_syscall_wait( pid_t pid, int signal );
    void start_handling( SyscallHandlerTask *task );
    void end_handling();
    void uses_buffers();
    void verify_syscall_success( pid_t pid, int sc_num, const char *exception_message ) const;
    void generate_syscall( pid_t pid ) const;

    int_ptr proxy_mmap(const char *exception_message, pid_t pid,
            int_ptr addr, size_t length, int prot, int flags, int fd, off_t offset);
    void proxy_munmap(const char *exception_message, pid_t pid,
                    int_ptr addr, size_t length);
    int proxy_open(const char *exception_message, pid_t pid,
            int_ptr pathname, int flags, mode_t mode = 0666);
    void proxy_close(const char *exception_message, pid_t pid,
            int fd);

    ptlib::WAIT_RET get_wait_state() const { return m_wait_state; }
    int get_wait_status() const { return m_wait_status; }
    long get_wait_parsed_status() const { return m_wait_parsed_status; }
private:
    pid_state( const pid_state &rhs ) = delete;
    pid_state &operator=( const pid_state &rhs ) = delete;
};

static inline std::ostream &operator<< (std::ostream &strm, pid_state::state wait_ret)
{
#define PRODUCE_CASE(_state) case pid_state::state::_state: strm<<#_state; break
    switch( wait_ret ) {
        PRODUCE_CASE(INIT);
        PRODUCE_CASE(NEW_ROOT);
        PRODUCE_CASE(NEW_CHILD);
        PRODUCE_CASE(NONE);
        PRODUCE_CASE(KERNEL);
        PRODUCE_CASE(WAITING);
        PRODUCE_CASE(WAKEUP);
    }
#undef PRODUCE_CASE

    return strm;
}

typedef void (*sys_callback)( int sc_num, pid_t pid, pid_state *state );
struct syscall_hook {
    sys_callback func;
    const char *name;

    syscall_hook() : func(NULL), name(NULL)
    {
    }
    syscall_hook( sys_callback _func, const char *_name ) : func(_func), name(_name)
    {
    }
};

#endif // PARENT_H
