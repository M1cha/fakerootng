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

#include <errno.h>

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
        ptlib_set_retval( pid, state->uid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_geteuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, state->euid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_getgid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, state->gid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

bool sys_getegid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        break;
    case pid_state::RETURN:
        ptlib_set_retval( pid, state->egid );
        state->state=pid_state::NONE;
        break;
    }

    return true;
}

#ifdef SYS_getresuid
bool sys_getresuid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        
        // Do not trust the syscall not to change the pointers
        state->saved_state[0]=(void *)ptlib_get_argument( pid, 1 );
        state->saved_state[1]=(void *)ptlib_get_argument( pid, 2 );
        state->saved_state[2]=(void *)ptlib_get_argument( pid, 3 );
        break;
    case pid_state::RETURN:
        if( ptlib_success(pid, sc_num) ) {
            ptlib_set_mem( pid, state->saved_state[0], &state->uid, sizeof(state->uid) );
            ptlib_set_mem( pid, state->saved_state[1], &state->euid, sizeof(state->euid) );
            ptlib_set_mem( pid, state->saved_state[2], &state->suid, sizeof(state->suid) );
        }
        state->state=pid_state::NONE;
        break;
    }

    return true;
}
#endif

#ifdef SYS_getresgid
bool sys_getresgid( int sc_num, pid_t pid, pid_state *state )
{
    switch( state->state ) {
    default:
    case pid_state::NONE:
        state->state=pid_state::RETURN;
        
        // Do not trust the syscall not to change the pointers
        state->saved_state[0]=(void *)ptlib_get_argument( pid, 1 );
        state->saved_state[1]=(void *)ptlib_get_argument( pid, 2 );
        state->saved_state[2]=(void *)ptlib_get_argument( pid, 3 );
        break;
    case pid_state::RETURN:
        if( ptlib_success(pid, sc_num) ) {
            ptlib_set_mem( pid, state->saved_state[0], &state->gid, sizeof(state->gid) );
            ptlib_set_mem( pid, state->saved_state[1], &state->egid, sizeof(state->egid) );
            ptlib_set_mem( pid, state->saved_state[2], &state->sgid, sizeof(state->sgid) );
        }
        state->state=pid_state::NONE;
        break;
    }

    return true;
}
#endif

bool sys_getgroups( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        ptlib_set_syscall(pid, PREF_NOP);
        state->state=pid_state::REDIRECT2;

        // Store the arguments for later
        state->context_state[0]=ptlib_get_argument( pid, 1 );
        state->context_state[1]=ptlib_get_argument( pid, 2 );
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        // What is the size?
        if( state->context_state[0]==0 ) {
            // Merely report the number of groups we have
            ptlib_set_retval( pid, state->groups.size() );
        } else if( state->context_state[0]<state->groups.size() ) {
            // Not enough room
            ptlib_set_error( pid, state->orig_sc, EINVAL );
        } else {
            unsigned int count=0;
            gid_t *groups=(gid_t *)state->context_state[1];
            for( std::set<gid_t>::const_iterator i=state->groups.begin(); i!=state->groups.end(); ++i, ++count ) {
                ptlib_set_mem( pid, &*i, groups+count, sizeof(gid_t) );
            }

            ptlib_set_retval( pid, count );
        }
    }

    return true;
}

bool sys_setuid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        // Do we let the syscall proceed?
        state->context_state[0]=ptlib_get_argument( pid, 1 );

        // NOP the actual call
        ptlib_set_syscall( pid, PREF_NOP );
        state->state==pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Let's see if we want to perform the action
        uid_t uid=(uid_t)state->context_state[0];
        if( state->euid==ROOT_UID ) {
            // Super user version
            state->uid=state->euid=state->suid=state->fuid=uid;
            ptlib_set_retval( pid, 0 );
        } else if( state->uid==uid || state->suid==uid ) {
            // Regular user, but with an operation that is ok
            state->euid=uid;
            ptlib_set_retval (pid, 0 );
        } else {
            // No permission
            ptlib_set_error( pid, state->orig_sc, EPERM );
        }

        state->state==pid_state::NONE;
    }

    return true;
}
