#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "parent.h"

#define DECLARE_SYSFUNC(name) void sys_##name( pid_t pid, pid_state *state );

DECLARE_SYSFUNC(geteuid)
DECLARE_SYSFUNC(getuid)
DECLARE_SYSFUNC(fork)

#endif // SYSCALLS_H
