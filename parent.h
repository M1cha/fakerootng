#ifndef PARENT_H
#define PARENT_H

#include <sys/time.h>
#include <sys/resource.h>

#include <list>

#include <stdio.h>

#include "platform_specific.h"

int process_children(pid_t first_child, int comm_fd);

#define NUM_SAVED_STATES 3

struct pid_state {
    enum states { INIT, NONE, RETURN, REDIRECT1, REDIRECT2, ALLOCATE, ALLOC_RETURN } state;
    int orig_sc; // Original system call
    void *memory; // Where and how much mem do we have inside the process's address space
    size_t mem_size;
    void *context_state[NUM_SAVED_STATES];
    void *saved_state[PTLIB_STATE_SIZE];

#if !PTLIB_PARENT_CAN_WAIT
    struct waiting_signal {
        pid_t pid;
        int status;
        struct rusage usage;
        
        waiting_signal( pid_t _pid, int _status, const struct rusage &_usage ) : pid(_pid), status(_status), usage(_usage)
        {
        }
    };
    std::list<waiting_signal> waiting_signals;

    pid_t parent;
#endif // PTLIB_PARENT_CAN_WAIT

    pid_state() : state(INIT), memory(NULL), mem_size(0)
#if !PTLIB_PARENT_CAN_WAIT
        , parent(1)
#endif // PTLIB_PARENT_CAN_WAIT
    {
    }
};

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

#endif /* PARENT_H */
