#ifndef PARENT_H
#define PARENT_H

#include <sys/time.h>
#include <sys/resource.h>

#include <list>

#include <stdio.h>

#include "arch/platform.h"
#include "platform_specific.h"

int process_children(pid_t first_child, int comm_fd, pid_t session_id );
int process_sigchld( pid_t pid, enum PTLIB_WAIT_RET wait_state, int status, long ret );

#define NUM_SAVED_STATES 4

struct pid_state {
    enum states { INIT, NONE, RETURN, REDIRECT1, REDIRECT2, ALLOCATE, ALLOC_RETURN, WAITING } state;
    int orig_sc; // Original system call
    void *memory; // Where and how much mem do we have inside the process's address space
    size_t mem_size;
    void *context_state[NUM_SAVED_STATES];
    void *saved_state[PTLIB_STATE_SIZE];

    // "wait" simulation and recursive debuggers support
    pid_t debugger, parent; // Which process thinks it's ptracing/parenting this one
    int num_children, num_debugees; // How many child/debugged processes we have
    int trace_mode; // Which ptrace mode was used to run the process
    pid_t session_id;

// Values for trace_mode
#define TRACE_DETACHED  0x0
#define TRACE_CONT      0x1
#define TRACE_SYSCALL   0x2
#define TRACE_SINGLSTEP 0x3
#define TRACE_MASK1     0x7
#define TRACE_STOPPED1  0x10
#define TRACE_STOPPED2  0x20
#define TRACE_MASK2     0x70

    struct wait_state {
        struct rusage usage;
        pid_t pid;
        int status;
    };
    std::list<wait_state> waiting_signals;

    pid_state() : state(INIT), memory(NULL), mem_size(0), debugger(0), parent(0), num_children(0), num_debugees(0),
        trace_mode(TRACE_DETACHED), session_id(0)
    {
    }
};

pid_state *lookup_state( pid_t pid );

typedef bool (*sys_callback)( int sc_num, pid_t pid, pid_state *state );
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

bool allocate_process_mem( pid_t pid, pid_state *state, int sc_num );

void dump_registers( pid_t pid );

#endif /* PARENT_H */
