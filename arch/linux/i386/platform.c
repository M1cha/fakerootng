#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
//#include <sys/user.h>
#include <linux/user.h>
#include <asm-i486/ptrace.h>
#include <sys/syscall.h>
#include <errno.h>

#include <stdio.h>
#include <assert.h>

#include "../../platform.h"

int ptlib_get_syscall( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 4*ORIG_EAX, 0 );
}

void *ptlib_get_argument( pid_t pid, int argnum )
{
    if( argnum<6 && argnum>0 )
        return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*(argnum-1), 0 );

    /* Illegal arg num */
    fprintf(stderr, "Illegal argnum %d was asked for\n", argnum );

    return NULL;
}

void *ptlib_get_retval( pid_t pid )
{
    return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*EAX );
}

void ptlib_set_retval( pid_t pid, void *val )
{
    ptrace( PTRACE_POKEUSER, pid, 4*EAX, val );
}

int ptlib_success( pid_t pid, int sc_num )
{
    void *ret=ptlib_get_retval( pid );

    switch( sc_num ) {
    case __NR_stat:
    case __NR_stat64:
    case __NR_fstat:
    case __NR_fstat64:
    case __NR_lstat:
    case __NR_lstat64:
        return ((int)ret)>=0;
    case __NR_mmap:
        /* -errno on error */
        return ((unsigned int)ret)<0xfffff000u;
    default:
        assert(0); /* We tried to assume about an unknown syscall */
        return 0;
    }
}

