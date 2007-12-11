#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
//#include <sys/user.h>
#include <linux/user.h>
#include <asm-i486/ptrace.h>

#include <stdio.h>

#include "../../platform.h"

void *ptlib_get_syscall( pid_t pid )
{
    return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*ORIG_EAX, 0 );
}

void *ptlib_get_argument( pid_t pid, int argnum )
{
    if( argnum<6 && argnum>0 )
        return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*(argnum-1), 0 );

    /* Illegal arg num */
    fprintf(stderr, "Illegal argnum %d was asked for\n", argnum );

    return NULL;
}
