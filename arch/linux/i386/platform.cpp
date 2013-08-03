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
#include <asm/ptrace.h>
#include <sys/syscall.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>

#include "../../platform.h"
#include "../os.h"

#define mem_offset 8

namespace ptlib {

static const unsigned char memory_image[mem_offset]=
{
    0xcd, 0x80, /* int 0x80 - syscall */
    0x00, 0x00, /* Pad */
};


void init()
{
    // Nothing to be done on this platform
}

int cont( int request, pid_t pid, int signal )
{
    return linux_continue( __ptrace_request(request), pid, signal );
}

const void *prepare_memory( )
{
    return memory_image;
}

size_t prepare_memory_len()
{
    return mem_offset;
}

void prepare( pid_t pid )
{
    linux_prepare( pid );
}

int wait( pid_t *pid, int *status, extra_data *data, int async )
{
    return linux_wait( pid, status, data, async );
}

long parse_wait( pid_t pid, int status, enum WAIT_RET *type )
{
    return linux_parse_wait( pid, status, type );
}

int get_syscall( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 4*ORIG_EAX, 0 );
}

int set_syscall( pid_t pid, int sc_num )
{
    return ptrace( PTRACE_POKEUSER, pid, 4*ORIG_EAX, sc_num );
}

int generate_syscall( pid_t pid, int sc_num, int_ptr base_memory )
{
    /* Cannot generate a syscall per-se. Instead, set program counter to an instruction known to generate one */
    ptrace( PTRACE_POKEUSER, pid, 4*EAX, sc_num );
    ptrace( PTRACE_POKEUSER, pid, 4*EIP, base_memory-mem_offset );

    return 1;
}

int_ptr get_argument( pid_t pid, int argnum )
{
    if( argnum<6 && argnum>0 )
        return ptrace( PTRACE_PEEKUSER, pid, 4*(argnum-1), 0 );

    /* Illegal arg num */
    dlog("ptlib_get_argument: " PID_F " Illegal argnum %d was asked for\n", pid, argnum );
    errno=EINVAL;

    return -1;
}

int set_argument( pid_t pid, int argnum, int_ptr value )
{
    if( argnum<=6 && argnum>0 )
        return ptrace( PTRACE_POKEUSER, pid, 4*(argnum-1), value )==0;

    /* Illegal arg num */
    dlog("ptlib_set_argument: " PID_F " Illegal argnum %d was asked for\n", pid, argnum );
    errno=EINVAL;

    return -1;
}

int_ptr get_retval( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 4*EAX );
}

void set_retval( pid_t pid, int_ptr val )
{
    ptrace( PTRACE_POKEUSER, pid, 4*EAX, val );
}

int get_error( pid_t pid, int sc_num )
{
    return -(int)get_retval( pid );
}

void set_error( pid_t pid, int sc_num, int error )
{
    set_retval( pid, -error );
}

int success( pid_t pid, int sc_num )
{
    int ret=get_retval( pid );

    switch( sc_num ) {
    case SYS_mmap:
    case SYS_mmap2:
        /* -errno on error */
        return ((unsigned int)ret)<0xfffff000u;
    default:
        return ret>=0;
    }
}

int get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len )
{
    return linux_get_mem( pid, process_ptr, local_ptr, len );
}

int set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len )
{
    return linux_set_mem( pid, local_ptr, process_ptr, len );
}

void save_state( pid_t pid, void *buffer )
{
    ptrace( __ptrace_request(PTRACE_GETREGS), pid, 0, buffer );
}

void restore_state( pid_t pid, const void *buffer )
{
    ptrace( __ptrace_request(PTRACE_SETREGS), pid, 0, buffer );
}

int get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen )
{
    return linux_get_string( pid, process_ptr, local_ptr, maxlen );
}

int set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr )
{
    return linux_set_string( pid, local_ptr, process_ptr );
}

ssize_t get_cwd( pid_t pid, char *buffer, size_t buff_size )
{
    return linux_get_cwd( pid, buffer, buff_size );
}

ssize_t get_fd( pid_t pid, int fd, char *buffer, size_t buff_size )
{
    return linux_get_fd( pid, fd, buffer, buff_size );
}

pid_t get_parent( pid_t pid )
{
    return linux_get_parent(pid);
}

int fork_enter( pid_t pid, int orig_sc, int_ptr process_mem, void *our_mem, void *registers[STATE_SIZE],
        int_ptr context[FORK_CONTEXT_SIZE] )
{
    return linux_fork_enter( pid, orig_sc, process_mem, our_mem, registers, context );
}

int fork_exit( pid_t pid, pid_t *newpid, void *registers[STATE_SIZE], int_ptr context[FORK_CONTEXT_SIZE] )
{
    return linux_fork_exit( pid, newpid, registers, context );
}

}; // End of namespace ptlib
