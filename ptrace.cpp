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

#include <sys/ptrace.h>
#include <errno.h>

#include "syscalls.h"
#include "arch/platform.h"

// Retruns true of the specified pid has permission to perform a ptrace operation
static bool verify_permission( pid_t pid, pid_state *state )
{
    pid_t traced=(pid_t)state->context_state[1];

    // First, find out whether the pid we work on even exists

    pid_state *child_state=lookup_state( traced );
    if( child_state==NULL || child_state->debugger!=pid ) {
        errno=ESRCH;
        return false;
    }

    return true;
}

static bool begin_trace( pid_t debugger, pid_t child )
{
    pid_state *child_state=lookup_state( child );
    if( child_state==NULL || child_state->debugger!=0 ) {
        errno=EPERM;
        return false;
    }

    child_state->debugger=debugger;
    child_state->trace_mode=PTRACE_CONT;

    return true;
}

bool sys_ptrace( int sc_num, pid_t pid, pid_state *state )
{
    bool ret=true;

    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 1 ); // request
        state->context_state[1]=ptlib_get_argument( pid, 2 ); // pid
        state->context_state[2]=ptlib_get_argument( pid, 3 ); // addr
        state->context_state[3]=ptlib_get_argument( pid, 4 ); // data

        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        // Let's see what whether we need to succeed
        switch( (int)state->context_state[0] ) {
        case PTRACE_TRACEME:
            if( begin_trace( state->parent, pid ) ) {
                ptlib_set_retval( pid, 0 );
            } else {
                ptlib_set_error( pid, state->orig_sc, errno );
            }
            break;
        case PTRACE_ATTACH:
            if( begin_trace( pid, (pid_t)state->context_state[1] ) ) {
                ptlib_set_retval( pid, 0 );
            } else {
                ptlib_set_error( pid, state->orig_sc, errno );
            }
            break;
        case PTRACE_PEEKTEXT:
        case PTRACE_PEEKDATA:
        case PTRACE_PEEKUSER:
        case PTRACE_POKETEXT:
        case PTRACE_POKEDATA:
        case PTRACE_POKEUSER:
            break;
        case PTRACE_GETREGS:
        case PTRACE_GETFPREGS:
            break;
        case PTRACE_SETREGS:
        case PTRACE_SETFPREGS:
            break;
        case PTRACE_GETSIGINFO:
            break;
        case PTRACE_SETSIGINFO:
            break;
        case PTRACE_SINGLESTEP:
        case PTRACE_CONT:
        case PTRACE_SYSCALL:
            if( verify_permission( pid, state ) ) {
                state->trace_mode=(int)state->context_state[0];
                __ptrace_request req=(__ptrace_request)state->trace_mode;
                if( req==PTRACE_CONT )
                    req=PTRACE_SYSCALL;
                long rc=ptrace( req, (pid_t)state->context_state[1], state->context_state[2],
                    state->context_state[3] );

                if( rc!=-1 ) {
                    ptlib_set_retval( pid, (void *)rc );
                } else
                    ptlib_set_error( pid, sc_num, errno );
            }
            break;
        case PTRACE_KILL:
            break;
        case PTRACE_DETACH:
            break;
        default:
            dlog("ptrace: "PID_F" Unsupported option %x\n", pid, (int)state->context_state[0] );
            ptlib_set_error(pid, state->orig_sc, EPERM);
            break;
        }
    }

    return ret;
}
