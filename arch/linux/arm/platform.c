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
#include <sys/wait.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../platform.h"
#include "../os.h"

#ifndef is_wide_instruction
#define is_wide_instruction(instr)      ((unsigned)(instr) >= 0xe800)
#endif

static int current_sc_is_thumb = 0;

int_ptr get_pc(pid_t pid) {
    return ptrace( PTRACE_PEEKUSER, pid, 60, 0 );
}

int_ptr get_ip(pid_t pid) {
    return ptrace( PTRACE_PEEKUSER, pid, 48, 0 );
}

int_ptr get_cpsr(pid_t pid) {
    return ptrace( PTRACE_PEEKUSER, pid, 16*4, 0 );
}

int_ptr is_thumb_mode(pid_t pid) {
    return !!(get_cpsr(pid) & PSR_T_BIT);
}

#define mem_offset 8
static const char memory_image[mem_offset]=
{
    0x00, 0x00, 0x00, 0xef, /* swi 0 */
};

static const char memory_image_thumb[mem_offset]=
{
    0x00, 0xdf, /* swi 0 */
    0x00, 0x00, /* padding */
};

void ptlib_init()
{
    // Nothing to be done on this platform
}

int ptlib_continue( int request, pid_t pid, int signal )
{
    return ptlib_linux_continue( request, pid, signal );
}

const void *ptlib_prepare_memory( )
{
    if(current_sc_is_thumb)
        return memory_image_thumb;
    else
        return memory_image;
}


size_t ptlib_prepare_memory_len()
{
    return mem_offset;
}

void ptlib_prepare( pid_t pid )
{
    ptlib_linux_prepare( pid );
}

int ptlib_wait( pid_t *pid, int *status, ptlib_extra_data *data, int async )
{
    return ptlib_linux_wait( pid, status, data, async );
}

long ptlib_parse_wait( pid_t pid, int status, enum PTLIB_WAIT_RET *type )
{
    return ptlib_linux_parse_wait( pid, status, type );
}

int ptlib_get_syscall( pid_t pid )
{
    current_sc_is_thumb = is_thumb_mode(pid);
    return ptrace( PTRACE_PEEKUSER, pid, 28, 0 );
}

int ptlib_set_syscall( pid_t pid, int sc_num )
{
    /* ARM requires us to call this function to set the system call. */
    ptrace( PTRACE_SET_SYSCALL, pid, 0, sc_num );

    return ptrace( PTRACE_POKEUSER, pid, 28, sc_num );
}

int ptlib_generate_syscall( pid_t pid, int sc_num, int_ptr base_memory )
{
    /* Cannot generate a syscall per-se. Instead, set program counter to an instruction known to generate one */
    ptlib_set_syscall(pid, sc_num);
    ptrace( PTRACE_POKEUSER, pid, 60, base_memory-mem_offset );

    return 1;
}

int_ptr ptlib_get_argument( pid_t pid, int argnum )
{
    if( argnum<6 && argnum>0 )
        return ptrace( PTRACE_PEEKUSER, pid, 4*(argnum-1), 0 );

    /* Illegal arg num */
    dlog("ptlib_get_argument: "PID_F" Illegal argnum %d was asked for\n", pid, argnum );
    errno=EINVAL;

    return -1;
}

int ptlib_set_argument( pid_t pid, int argnum, int_ptr value )
{
    if( argnum<=6 && argnum>0 ) {
        // ARM_7475_1 workaround
        if(argnum>=5 && get_ip(pid)==0) {
            // backup some data
            uint32_t instr = 0;
            int_ptr a1 = ptlib_get_argument(pid, 1);
            int_ptr scno = ptlib_get_syscall(pid);
            ptlib_get_mem(pid, get_pc(pid), &instr, sizeof(instr));

            // change syscall to getpid
            ptlib_set_syscall(pid, SYS_getpid);
            
            // continue and wait for post
            ptlib_continue(PTRACE_SYSCALL, pid, 0);
            waitpid(pid, NULL, __WALL);

            // set argument
            int rc = ptrace( PTRACE_POKEUSER, pid, 4*(argnum-1), value )==0;

            // go back and wait for pre
            int step_back_size = is_wide_instruction(instr)?4:2;
            ptrace( PTRACE_POKEUSER, pid, 60, get_pc(pid)-step_back_size );
            ptlib_continue(PTRACE_SYSCALL, pid, 0);
            waitpid(pid, NULL, __WALL);

            // restore regs
            ptlib_set_syscall(pid, scno);
            ptlib_set_argument(pid, 1, a1);

            return rc;
        }

        return ptrace( PTRACE_POKEUSER, pid, 4*(argnum-1), value )==0;
    }

    /* Illegal arg num */
    dlog("ptlib_set_argument: "PID_F" Illegal argnum %d was asked for\n", pid, argnum );
    errno=EINVAL;

    return -1;
}

int_ptr ptlib_get_retval( pid_t pid )
{
    return ptrace( PTRACE_PEEKUSER, pid, 0 );
}

void ptlib_set_retval( pid_t pid, int_ptr val )
{
    ptrace( PTRACE_POKEUSER, pid, 0, val );
}

int ptlib_get_error( pid_t pid, int sc_num )
{
    return -(int)ptlib_get_retval( pid );
}

void ptlib_set_error( pid_t pid, int sc_num, int error )
{
    ptlib_set_retval( pid, -error );
}

int ptlib_success( pid_t pid, int sc_num )
{
    int ret=ptlib_get_retval( pid );

    switch( sc_num ) {
    case SYS_mmap2:
        /* -errno on error */
        return ((unsigned int)ret)<0xfffff000u;
    default:
        return ret>=0;
    }
}

int ptlib_get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len )
{
    return ptlib_linux_get_mem( pid, process_ptr, local_ptr, len );
}

int ptlib_set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len )
{
    return ptlib_linux_set_mem( pid, local_ptr, process_ptr, len );
}

void ptlib_save_state( pid_t pid, void *buffer )
{
    ptrace( PTRACE_GETREGS, pid, 0, buffer );
}

void ptlib_restore_state( pid_t pid, const void *buffer )
{
    const struct pt_regs* regs = buffer;
    ptlib_set_syscall(pid, regs->ARM_r7);

    ptrace( PTRACE_SETREGS, pid, 0, buffer );
}

int ptlib_get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen )
{
    return ptlib_linux_get_string( pid, process_ptr, local_ptr, maxlen );
}

int ptlib_set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr )
{
    return ptlib_linux_set_string( pid, local_ptr, process_ptr );
}

ssize_t ptlib_get_cwd( pid_t pid, char *buffer, size_t buff_size )
{
    return ptlib_linux_get_cwd( pid, buffer, buff_size );
}

ssize_t ptlib_get_fd( pid_t pid, int fd, char *buffer, size_t buff_size )
{
    return ptlib_linux_get_fd( pid, fd, buffer, buff_size );
}

pid_t ptlib_get_parent( pid_t pid )
{
    return ptlib_linux_get_parent(pid);
}

int ptlib_fork_enter( pid_t pid, int orig_sc, int_ptr process_mem, void *our_mem, void *registers[PTLIB_STATE_SIZE],
        int_ptr context[FORK_CONTEXT_SIZE] )
{
    return ptlib_linux_fork_enter( pid, orig_sc, process_mem, our_mem, registers, context );
}

int ptlib_fork_exit( pid_t pid, pid_t *newpid, void *registers[PTLIB_STATE_SIZE], int_ptr context[FORK_CONTEXT_SIZE] )
{
    return ptlib_linux_fork_exit( pid, newpid, registers, context );
}
