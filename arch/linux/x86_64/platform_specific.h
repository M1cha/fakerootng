#ifndef PLATFORM_SPECIFIC_H
#define PLATFORM_SPECIFIC_H

#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/user.h>

/* Specially defined 32 bit syscalls that don't have a 64 syscall, but need to be handled */
#define __NR_waitpid -3
#define SYS_waitpid __NR_waitpid
#define __NR_oldstat -4
#define SYS_oldstat __NR_oldstat
#define __NR_oldfstat -5
#define SYS_oldfstat __NR_oldfstat
#define __NR_oldlstat -6
#define SYS_oldlstat __NR_oldlstat
#define __NR_sigreturn -7
#define SYS_sigreturn __NR_sigreturn
#define __NR_mmap2 -8
#define SYS_mmap2 __NR_mmap2
#define __NR_stat64 -9
#define SYS_stat64 __NR_stat64
#define __NR_lstat64 -10
#define SYS_lstat64 __NR_lstat64
#define __NR_fstat64 -11
#define SYS_fstat64 __NR_fstat64
#define __NR_lchown32 -12
#define SYS_lchown32 __NR_lchown32
#define __NR_getuid32 -13
#define SYS_getuid32 __NR_getuid32
#define __NR_getgid32 -14
#define SYS_getgid32 __NR_getgid32
#define __NR_geteuid32 -15
#define SYS_geteuid32 __NR_geteuid32
#define __NR_getegid32 -16
#define SYS_getegid32 __NR_getegid32
#define __NR_setreuid32 -17
#define SYS_setreuid32 __NR_setreuid32
#define __NR_setregid32 -18
#define SYS_setregid32 __NR_setregid32
#define __NR_getgroups32 -19
#define SYS_getgroups32 __NR_getgroups32
#define __NR_setgroups32 -20
#define SYS_setgroups32 __NR_setgroups32
#define __NR_fchown32 -21
#define SYS_fchown32 __NR_fchown32
#define __NR_setresuid32 -22
#define SYS_setresuid32 __NR_setresuid32
#define __NR_getresuid32 -23
#define SYS_getresuid32 __NR_getresuid32
#define __NR_setresgid32 -24
#define SYS_setresgid32 __NR_setresgid32
#define __NR_getresgid32 -25
#define SYS_getresgid32 __NR_getresgid32
#define __NR_chown32 -26
#define SYS_chown32 __NR_chown32
#define __NR_setuid32 -27
#define SYS_setuid32 __NR_setuid32
#define __NR_setgid32 -28
#define SYS_setgid32 __NR_setgid32
#define __NR_setfsuid32 -29
#define SYS_setfsuid32 __NR_setfsuid32
#define __NR_setfsgid32 -30
#define SYS_setfsgid32 __NR_setfsgid32
#define __NR_fstatat64 -31
#define SYS_fstatat64 __NR_fstatat64

#define SYS_X86_32_OFFSET 31

/* An unsigned int as long as a pointer */
typedef unsigned long int_ptr;

namespace ptlib {

/* Marks the library as supporting debugging children */
static const bool SUPPORTS_FORK=true;
static const bool SUPPORTS_VFORK=true;
static const bool SUPPORTS_CLONE=true;

static const bool PARENT_CAN_WAIT=true;

/* This is defined to true if the platform sends a SIGTRAP to the process after a successful execve if it's being
 * traced
 */
static const bool TRAP_AFTER_EXEC=true;

constexpr const size_t prepare_memory_len = 8;

typedef struct rusage extra_data;

typedef user_regs_struct cpu_state;

namespace preferred {
static const int NOP = SYS_getuid;
static const int MMAP = SYS_mmap;
static const int MUNMAP = SYS_munmap;
static const int OPEN = SYS_open;
static const int CLOSE = SYS_close;
static const int FSTAT = SYS_fstat;
static const int LSTAT = SYS_lstat;
static const int STAT = SYS_stat;
static const int FSTATAT = SYS_newfstatat;
};

}; // End of namespace ptlib

/* Platform specific format specifiers for printing pid, dev and inode */
#define PID_F "%d"

#endif /* PLATFORM_SPECIFIC_H */
