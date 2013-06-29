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
void init_debugger();
// Shutdown the debugger environment
void shutdown_debugger();
// Main processing loop
int process_children( daemonProcess *daemon );

class SyscallHandlerTask;

class pid_state {
public:
    enum state { INIT, USER, KERNEL, WAITING };
    
private:
    // The credentials (including the Linux specific file system UID)
    uid_t m_uid, m_euid, m_suid, m_fsuid;
    gid_t m_gid, m_egid, m_sgid, m_fsgid;
    std::set<gid_t> m_groups;

    enum state m_state = INIT;
    SyscallHandlerTask *m_task = nullptr;

public:
    pid_state() :
        m_uid(0), m_euid(0), m_suid(0), m_fsuid(0),
        m_gid(0), m_egid(0), m_sgid(0), m_fsgid(0)
    {
    }

    enum state get_state() const
    {
        return m_state;
    }

private:
    pid_state( const pid_state &rhs ) = delete;
    pid_state &operator=( const pid_state &rhs ) = delete;
};

class SyscallHandlerTask : public worker_queue::worker_task
{
public:
    SyscallHandlerTask( pid_t pid, pid_state *proc_state, enum PTLIB_WAIT_RET ptlib_status, int wait_status,
            long parsed_status ) :
        m_pid( pid ),
        m_proc_state( proc_state ),
        m_ptlib_status( ptlib_status ),
        m_wait_status( wait_status ),
        m_parsed_status( parsed_status )
    {
    }

protected:
    pid_t m_pid;
    pid_state *m_proc_state;
    PTLIB_WAIT_RET m_ptlib_status;
    int m_wait_status;
    long m_parsed_status;
};

#endif // PARENT_H
