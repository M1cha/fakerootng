#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "parent.h"

#define DECLARE_SYSFUNC(name) bool sys_##name( pid_t pid, pid_state *state );

DECLARE_SYSFUNC(geteuid)
DECLARE_SYSFUNC(getuid)
DECLARE_SYSFUNC(fork)
DECLARE_SYSFUNC(wait4)

#endif // SYSCALLS_H
