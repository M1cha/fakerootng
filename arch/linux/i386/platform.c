/*
    Fakeroot Next Generation - run command with fake root privileges
    This program is copyrighted. Copyright information is available at the
    AUTHORS file at the root of the source tree for the fakeroot-ng project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "config.h"

#include <sys/types.h>
#include <sys/ptrace.h>
//#include <sys/user.h>
#include <linux/user.h>
#include <asm/ptrace.h>
#include <sys/syscall.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>

#include "../../platform.h"
#include "../os.h"

static const char memory_image[]=
{
    0xcd, 0x80, /* int 0x80 - syscall */
    0x00, 0x00, /* Pad */
};

static int mem_offset=((sizeof(memory_image)+7)/8)*8;

void ptlib_init()
{
    // Nothing to be done on this platform
}

int ptlib_continue( int request, pid_t pid, int signal )
{
    return ptlib_linux_continue( request, pid, signal );
}

void ptlib_prepare_memory( pid_t pid, void **memory, size_t *size )
{
    void *orig_mem=*memory;

    /* Move the pointer to a multiple of 8 */
    (*memory)+=mem_offset;
    (*size)-=mem_offset;

    /* Copy the data over */
    ptlib_set_mem( pid, memory_image, orig_mem, sizeof( memory_image ) );
}

void ptlib_prepare( pid_t pid )
{
    ptlib_linux_prepare( pid );
}

int ptlib_wait( pid_t *pid, int *status, ptlib_extra_data *data )
{
    return ptlib_linux_wait( pid, status, data );
}

long ptlib_parse_wait( pid_t pid, int status, enum PTLIB_WAIT_RET *type )
{
    return ptlib_linux_parse_wait( pid, status, type );
}

int ptlib_get_syscall( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 4*ORIG_EAX, 0 );
}

int ptlib_set_syscall( pid_t pid, int sc_num )
{
    return ptrace( PTRACE_POKEUSER, pid, 4*ORIG_EAX, sc_num );
}

int ptlib_generate_syscall( pid_t pid, int sc_num, void *base_memory )
{
    /* Cannot generate a syscall per-se. Instead, set program counter to an instruction known to generate one */
    ptrace( PTRACE_POKEUSER, pid, 4*EAX, sc_num );
    ptrace( PTRACE_POKEUSER, pid, 4*EIP, base_memory-mem_offset );

    return 1;
}

void *ptlib_get_argument( pid_t pid, int argnum )
{
    if( argnum<6 && argnum>0 )
        return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*(argnum-1), 0 );

    /* Illegal arg num */
    fprintf(stderr, "Illegal argnum %d was asked for\n", argnum );

    return NULL;
}

int ptlib_set_argument( pid_t pid, int argnum, void *value )
{
    if( argnum<=6 && argnum>0 )
        return ptrace( PTRACE_POKEUSER, pid, 4*(argnum-1), value )==0;

    /* Illegal arg num */
    fprintf(stderr, "Illegal argnum %d was asked for\n", argnum );

    return 0;
}

void *ptlib_get_retval( pid_t pid )
{
    return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*EAX );
}

void ptlib_set_retval( pid_t pid, void *val )
{
    ptrace( PTRACE_POKEUSER, pid, 4*EAX, val );
}

int ptlib_get_error( pid_t pid, int sc_num )
{
    switch( sc_num ) {
    case SYS_chmod:
    case SYS_fchmod:
    case SYS_mmap:
    case SYS_mknod:
    case SYS_mkdir:
    case SYS_open:
    case SYS_chown:
    case SYS_fchown:
    case SYS_lchown:
    case SYS_stat64:
    case SYS_lstat64:
    case SYS_fstat64:
    case SYS_symlink:
    case SYS_execve:
        return -(int)ptlib_get_retval( pid );
    default:
        dlog("ptlib_get_error: %d syscall %d not supported - aborting\n", pid, sc_num );
        dlog(NULL); /* Flush the log before we crash */
        abort();
        return -(int)ptlib_get_retval( pid );
    }
}

void ptlib_set_error( pid_t pid, int sc_num, int error )
{
    ptlib_set_retval( pid, (void *)-error );
}

int ptlib_success( pid_t pid, int sc_num )
{
    void *ret=ptlib_get_retval( pid );

    switch( sc_num ) {
    case SYS_mmap:
    case SYS_mmap2:
        /* -errno on error */
        return ((unsigned int)ret)<0xfffff000u;
    default:
        return ((int)ret)>=0;
    }
}

int ptlib_get_mem( pid_t pid, void *process_ptr, void *local_ptr, size_t len )
{
    return ptlib_linux_get_mem( pid, process_ptr, local_ptr, len );
}

int ptlib_set_mem( pid_t pid, const void *local_ptr, void *process_ptr, size_t len )
{
    ptlib_linux_set_mem( pid, local_ptr, process_ptr, len );
}

void ptlib_save_state( pid_t pid, void *buffer )
{
    ptrace( PTRACE_GETREGS, pid, 0, buffer );
}

void ptlib_restore_state( pid_t pid, const void *buffer )
{
    ptrace( PTRACE_SETREGS, pid, 0, buffer );
}

int ptlib_get_string( pid_t pid, void *process_ptr, char *local_ptr, size_t maxlen )
{
    return ptlib_linux_get_string( pid, process_ptr, local_ptr, maxlen );
}

#if 0
int ptlib_set_string( pid_t pid, const char *local_ptr, void *process_ptr )
{
    return ptlib_linux_set_string( pid, local_ptr, process_ptr );
}
#endif
