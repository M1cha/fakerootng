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

#include "syscalls.h"
#include "arch/platform.h"

bool sys_getuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, 0 );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_fork( int sc_num, pid_t pid, pid_state *state )
{
    // Dummy handling for now
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_execve( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        if( log_level>0 ) {
            char cmd[PATH_MAX];
            ptlib_get_string( pid, ptlib_get_argument( pid, 1 ), cmd, sizeof(cmd) );
            dlog("execve: "PID_F" calling execve for executing %s\n", pid, cmd );
            dlog(NULL);
        }
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;

        if( ptlib_success( pid, sc_num ) ) {
            dlog("execve: "PID_F" successfully execed a new command\n", pid );

            // All memory allocations performed before the exec are now null and void
            state->memory=NULL;
            state->mem_size=0;

#if PTLIB_TRAP_AFTER_EXEC
            // The platform sends a SIGTRAP to the process after a successful execve, which results in us thinking it was
            // a syscall. We need to absorb it
            state->state=pid_state::REDIRECT2;
#endif
        } else {
            dlog("execve: "PID_F" failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)) );
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Nothing to do here
        state->state=pid_state::NONE;
    }

    return true;
}

bool sys_sigreturn( int sc_num, pid_t pid, pid_state *state )
{
    // This is not a function call. In particular, this "not function call" may wreak haevoc in our state keeping, and
    // thus the special handling
    if( state->state==pid_state::NONE ) {
        // Upon syscall exit, at least on Linux, the syscall is "-1"
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;
    }

    return true;
}
