#ifndef PARENT_H
#define PARENT_H

#include <sys/time.h>
#include <sys/resource.h>

#include <list>

#include <stdio.h>

#include "platform_specific.h"

void dlog( const char *format, ... );

int process_children(pid_t first_child, int comm_fd);

struct pid_state {
    enum { INIT, NONE, RETURN, WAIT_HALTED, WAIT4_HALTED, WAITPID_HALTED } state;
    void *memory; // Where and how much mem do we have inside the process's address space
    size_t mem_size;

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

    pid_state() : state(INIT), memory(NULL), mem_size(0), parent(1)
    {
    }
};

typedef bool (*sys_callback)( pid_t pid, pid_state *state );
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

#endif /* PARENT_H */
