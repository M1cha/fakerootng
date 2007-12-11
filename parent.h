#ifndef PARENT_H
#define PARENT_H

int process_children(pid_t first_child);

struct pid_state {
    enum { NONE, RETURN } state;

    pid_state() : state(NONE) {}
};

typedef void (*sys_callback)( pid_t pid, pid_state *state );

#endif /* PARENT_H */
