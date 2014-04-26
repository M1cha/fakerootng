#ifndef PARENT_H
#define PARENT_H

#include <set>

#include <sys/types.h>
#include <assert.h>

#include "arch/platform.h"
#include "worker_queue.h"

#include "unique_mmap.h"

class daemonProcess;

// Attach the debugger to a specific child
bool attach_debugger( pid_t child );
// Initialize the debugger environment
void init_debugger( daemonProcess *daemonProcess );
// Shutdown the debugger environment
void shutdown_debugger();
// Main processing loop
int process_children( daemonProcess *daemon );
// Requests to perform actions in the master thread
void handle_thread_request( int fd );

class SyscallHandlerTask;

class pid_state {
public:
    enum class state {
        INIT,     ///< Sanity - process should never actually do anything while in this state
        NEW,      ///< New process, recently registered. Should see a SIGSTOP next
        NONE,     ///< Idle state
        KERNEL,   ///< Inside a system call
        WAITING,  ///< A worker thread is waiting on this process
        WAKEUP,
    };
    
    // The credentials (including the Linux specific file system UID)
    uid_t m_uid, m_euid, m_suid, m_fsuid;
    gid_t m_gid, m_egid, m_sgid, m_fsgid;
    std::set<gid_t> m_groups;

    struct process_memory {
        int_ptr non_shared_addr = 0;
        int_ptr shared_addr = 0;
        unique_mmap shared_ptr;

        template <typename T> T* get_shared_addr()
        {
            return reinterpret_cast<T*>(shared_ptr.get<char>() + ptlib::prepare_memory_len);
        }
    } m_proc_mem;
private:
    enum state m_state = state::INIT;
    SyscallHandlerTask *m_task = nullptr;
    std::mutex m_wait_lock;
    std::condition_variable m_wait_condition;
    ptlib::WAIT_RET m_wait_state;
    int m_wait_status;
    long m_wait_parsed_status;

public:
    pid_state();

    enum state get_state() const
    {
        return m_state;
    }

    void setStateNone()
    {
        m_state=state::NONE;
    }

    void setStateNewInstance()
    {
        assert(m_state==state::INIT);
        m_state=state::NEW;
    }

    void setStateKernel()
    {
        assert(m_state==state::NONE);
        m_state=state::KERNEL;
    }

    void wait( const std::function< void ()> &callback );
    void wakeup( ptlib::WAIT_RET wait_state, int status, long parsed_status );
    void ptrace_syscall_wait( pid_t pid, int signal );
    void start_handling( SyscallHandlerTask *task );
    void end_handling();
    void uses_buffers( pid_t pid );
    void verify_syscall_success( pid_t pid, int sc_num, const char *exception_message ) const;
    void generate_syscall( pid_t pid ) const;

    int_ptr proxy_mmap(const char *exception_message, pid_t pid,
            int_ptr addr, size_t length, int prot, int flags, int fd, off_t offset);
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
        PRODUCE_CASE(NEW);
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
