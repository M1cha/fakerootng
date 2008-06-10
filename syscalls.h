#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "parent.h"

#define DECLARE_SYSFUNC(name) bool sys_##name( int sc_num, pid_t pid, pid_state *state );

// UID reporting
DECLARE_SYSFUNC(geteuid)
DECLARE_SYSFUNC(getuid)

// Process management
DECLARE_SYSFUNC(fork)
DECLARE_SYSFUNC(vfork)
DECLARE_SYSFUNC(wait4)
DECLARE_SYSFUNC(waitpid)
DECLARE_SYSFUNC(vfork)
DECLARE_SYSFUNC(clone)
//DECLARE_SYSFUNC(execve)
bool sys_execve( int sc_num, pid_t pid, pid_state *state, bool &post_trap );
DECLARE_SYSFUNC(sigreturn)
DECLARE_SYSFUNC(setsid)
DECLARE_SYSFUNC(ptrace)
DECLARE_SYSFUNC(kill)

// File handling
DECLARE_SYSFUNC(stat)
#ifdef SYS_fstatat64
DECLARE_SYSFUNC(fstatat64)
#endif
DECLARE_SYSFUNC(chmod)
DECLARE_SYSFUNC(fchmod)
DECLARE_SYSFUNC(fchmodat)
DECLARE_SYSFUNC(chown)
DECLARE_SYSFUNC(fchown)
DECLARE_SYSFUNC(lchown)
DECLARE_SYSFUNC(fchownat)
DECLARE_SYSFUNC(mknod)
DECLARE_SYSFUNC(mknodat)
DECLARE_SYSFUNC(open)
DECLARE_SYSFUNC(openat)
DECLARE_SYSFUNC(mkdir)
DECLARE_SYSFUNC(mkdirat)
DECLARE_SYSFUNC(symlink)
DECLARE_SYSFUNC(symlinkat)
DECLARE_SYSFUNC(link)
DECLARE_SYSFUNC(unlink)
DECLARE_SYSFUNC(unlinkat)
DECLARE_SYSFUNC(rename)
DECLARE_SYSFUNC(rmdir)
DECLARE_SYSFUNC(generic_chroot_support_param1)
DECLARE_SYSFUNC(generic_chroot_support_link_param1)
DECLARE_SYSFUNC(generic_chroot_support_param2)
DECLARE_SYSFUNC(generic_chroot_at)

DECLARE_SYSFUNC(chroot)
DECLARE_SYSFUNC(getcwd)
DECLARE_SYSFUNC(munmap)

// Meta required functions
DECLARE_SYSFUNC(mmap)

#endif // SYSCALLS_H
