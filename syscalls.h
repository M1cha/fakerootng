#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "parent.h"

#define DECLARE_SYSFUNC(name) bool sys_##name( int sc_num, pid_t pid, pid_state *state );

// UID reporting
DECLARE_SYSFUNC(geteuid)
DECLARE_SYSFUNC(getuid)

// Process management
DECLARE_SYSFUNC(fork)
//DECLARE_SYSFUNC(wait4)
DECLARE_SYSFUNC(vfork)
DECLARE_SYSFUNC(clone)
DECLARE_SYSFUNC(execve)
DECLARE_SYSFUNC(sigreturn)

// File handling
DECLARE_SYSFUNC(stat64)
DECLARE_SYSFUNC(chmod)
DECLARE_SYSFUNC(chown)
DECLARE_SYSFUNC(mknod)
DECLARE_SYSFUNC(open)
DECLARE_SYSFUNC(mkdir)
DECLARE_SYSFUNC(symlink)

// Meta required functions
DECLARE_SYSFUNC(mmap)

#endif // SYSCALLS_H
