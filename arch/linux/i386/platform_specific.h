#ifndef PLATFORM_SPECIFIC_H
#define PLATFORM_SPECIFIC_H

#include <asm-i486/ptrace.h>

/* Marks the library as supporting debugging children */
#define PTLIB_SUPPORTS_FORK 1
#define PTLIB_SUPPORTS_VFORK 1
#define PTLIB_SUPPORTS_CLONE 1

#define PTLIB_PARENT_CAN_WAIT 1

#define PTLIB_STATE_SIZE (FRAME_SIZE)

/* This is defined to 1 if the platform sends a SIGTRAP to the process after a successful execve if it's being traced */
#define PTLIB_TRAP_AFTER_EXEC 1

typedef unsigned long long ptlib_inode_t;

struct ptlib_stat64 {
        unsigned long long      dev;
        unsigned char   __pad0[4];

#define STAT64_HAS_BROKEN_ST_INO        1
        unsigned long   __ino;

        unsigned int    mode;
        unsigned int    nlink;

        unsigned long   uid;
        unsigned long   gid;

        unsigned long long      rdev;
        unsigned char   __pad3[4];

        long long       size;
        unsigned long   blksize;

        unsigned long long      blocks;      /* Number 512-byte blocks allocated. */

        unsigned long   atime;
        unsigned long   atime_nsec;

        unsigned long   mtime;
        unsigned int    mtime_nsec;

        unsigned long   ctime;
        unsigned long   ctime_nsec;

        unsigned long long      ino;
};

#endif // PLATFORM_SPECIFIC_H
