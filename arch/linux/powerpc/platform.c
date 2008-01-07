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

static const char memory_image[]=
{
    0x44, 0x00, 0x00, 0x02, /* sc */
};

static int mem_offset=((sizeof(memory_image)+7)/8)*8;

void ptlib_prepare_memory( pid_t pid, void **memory, size_t *size )
{
    void *orig_mem=*memory;

    /* Move the pointer to a multiple of 8 */
    (*memory)+=mem_offset;
    (*size)-=mem_offset;

    /* Copy the data over */
    ptlib_set_mem( pid, memory_image, orig_mem, sizeof( memory_image ) );
}

int ptlib_get_syscall( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 4*PT_R0, 0 );
}

int ptlib_set_syscall( pid_t pid, int sc_num )
{
    return ptrace( PTRACE_POKEUSER, pid, 4*PT_R0, sc_num );
}

int ptlib_generate_syscall( pid_t pid, int sc_num, void *base_memory )
{
    /* Cannot generate a syscall per-se. Instead, set program counter to an instruction known to generate one */
    ptrace( PTRACE_POKEUSER, pid, 4*PT_R0, sc_num );
    ptrace( PTRACE_POKEUSER, pid, 4*PT_NIP, base_memory-mem_offset );

    return 1;
}

void *ptlib_get_argument( pid_t pid, int argnum )
{
    if( argnum<6 && argnum>0 )
        return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*(PT_R3+argnum-1), 0 );

    /* Illegal arg num */
    dlog("Illegal argnum %d was asked for\n", argnum );

    return NULL;
}

int ptlib_set_argument( pid_t pid, int argnum, void *value )
{
    if( argnum<=6 && argnum>0 )
        return ptrace( PTRACE_POKEUSER, pid, 4*(PT_R3+argnum-1), value )==0;

    /* Illegal arg num */
    fprintf(stderr, "Illegal argnum %d was asked for\n", argnum );

    return 0;
}

void *ptlib_get_retval( pid_t pid )
{
    return (void *)ptrace( PTRACE_PEEKUSER, pid, 4*PT_R3 );
}

void ptlib_set_retval( pid_t pid, void *val )
{
    ptrace( PTRACE_POKEUSER, pid, 4*PT_R3, val );
}

#define SO_MASK 0x10000000

int ptlib_get_error( pid_t pid, int sc_num )
{
    return (int)ptlib_get_retval( pid );
}

int ptlib_success( pid_t pid, int sc_num )
{
    /* PowerPC sets the Summary Overflow upon error */
    unsigned long cr=ptrace( PTRACE_PEEKUSER, pid, PT_CCR*4, 0 );

    return (cr&SO_MASK)==0;
}

void ptlib_save_state( pid_t pid, void *buffer )
{
    int i;
    for( i=0; i<PTLIB_STATE_SIZE; ++i ) {
        ((long *)buffer)[i]=ptrace(PTRACE_PEEKUSER, pid, i*4, 0 );
    }
}

void ptlib_restore_state( pid_t pid, const void *buffer )
{
    int i;
    for( i=0; i<PTLIB_STATE_SIZE; ++i ) {
        ptrace(PTRACE_POKEUSER, pid, i*4, ((long *)buffer)[i] );
    }
}
