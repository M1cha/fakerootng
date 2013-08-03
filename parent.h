#ifndef PARENT_H
#define PARENT_H

#include <set>

#include <sys/types.h>
#include "arch/platform.h"
#include "worker_queue.h"

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
    enum state { INIT, NEW_INSTANCE, NONE, KERNEL, WAITING, WAKEUP };
    
private:
    // The credentials (including the Linux specific file system UID)
    uid_t m_uid, m_euid, m_suid, m_fsuid;
    gid_t m_gid, m_egid, m_sgid, m_fsgid;
    std::set<gid_t> m_groups;

    enum state m_state = INIT;
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
        m_state=NONE;
    }

    void setStateNewInstance()
    {
        assert(m_state==INIT);
        m_state=NEW_INSTANCE;
    }

    void wait( void (*callback)( void * ), void *opaq );
    void wakeup( ptlib::WAIT_RET wait_state, int status, long parsed_status );

    ptlib::WAIT_RET get_wait_state() const { return m_wait_state; }
    int get_wait_status() const { return m_wait_status; }
    long get_wait_parsed_status() const { return m_wait_parsed_status; }
private:
    pid_state( const pid_state &rhs ) = delete;
    pid_state &operator=( const pid_state &rhs ) = delete;
};

#endif // PARENT_H
