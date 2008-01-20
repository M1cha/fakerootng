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
        dlog("ptrace verify_permission: %d failed permission - not the debugger for "PID_F"\n", pid, traced);
        errno=ESRCH;
        return false;
    }

    return true;
}

static bool begin_trace( pid_t debugger, pid_t child )
{
    pid_state *child_state=lookup_state( child );
    pid_state *parent_state=lookup_state( debugger );

    if( child_state==NULL || parent_state==NULL || child_state->debugger!=0 ) {
        dlog("begin_trace: %d Failed to start trace for "PID_F": child_state=%p, parent_state=%p", debugger, child, child_state,
            parent_state );
        if( child_state!=NULL ) {
            dlog("child_state debugger="PID_F, child_state->debugger);
        }
        dlog("\n");

        errno=EPERM;
        return false;
    }

    child_state->debugger=debugger;
    child_state->trace_mode=PTRACE_CONT;
    parent_state->num_debugees++;

    return true;
}

void handle_cont_syscall( pid_t pid, pid_state *state )
{
    if( verify_permission( pid, state ) ) {
        pid_t child=(pid_t)state->context_state[1];
        pid_state *child_state=lookup_state( child );
        child_state->trace_mode=(int)state->context_state[0];
        __ptrace_request req=(__ptrace_request)child_state->trace_mode;
        dlog("ptrace: %d %s("PID_F")\n", pid, req==PTRACE_CONT?"PTRACE_CONT":"PTRACE_SYSCALL", child );

        long rc=0;

        if( child_state->state==pid_state::DEBUGGED1 ) {
            dlog("handle_cont_syscall: "PID_F" process "PID_F" was in pre-syscall hook\n", pid, child );
            // Need to restart the syscall
            int status=(int)child_state->context_state[1];
            PTLIB_WAIT_RET wait_state=(PTLIB_WAIT_RET)(int)child_state->context_state[0];
            long ret=ptlib_get_syscall( child );
            int sig=process_sigchld( child, wait_state, status, ret );
            // If our processing requested no special handling, use the signal requested by the debugger
            if( sig==0 )
                sig=(int)state->context_state[3];
            if( sig>=0 )
                rc=ptrace(PTRACE_SYSCALL, pid, 0, sig);
        } else if( child_state->state==pid_state::DEBUGGED2 ) {
            dlog("handle_cont_syscall: "PID_F" process "PID_F" was in post-syscall hook\n", pid, child );
            child_state->state=pid_state::NONE;
            rc=ptrace( PTRACE_SYSCALL, pid, 0, (int)state->context_state[3] );
        } else {
            // Our child was not stopped (at least, by us)
            // XXX What shall we do?

            dlog("handle_cont_syscall: "PID_F" process "PID_F" was started with no specific state\n", pid, child );
            rc=ptrace( PTRACE_SYSCALL, (pid_t)state->context_state[1], state->context_state[2],
                    state->context_state[3] );
        }

        if( rc!=-1 ) {
            dlog("ptrace: %d request successful\n", pid );
            ptlib_set_retval( pid, (void *)rc );
        } else {
            ptlib_set_error( pid, state->orig_sc, errno );
            dlog("ptrace: %d request failed: %s\n", pid, strerror(errno) );
        }
    }
}

bool handle_detach( pid_t pid, pid_state *state )
{
    if( verify_permission( pid, state ) ) {
        dlog("ptrace: %d PTRACE_DETACH("PID_F")\n", pid, (pid_t)state->context_state[1]);

        pid_state *child_state=lookup_state((pid_t)state->context_state[1]);

        child_state->debugger=0;
        state->num_debugees--;

        if( child_state->state==pid_state::DEBUGGED1 || child_state->state==pid_state::DEBUGGED2 )
            child_state->state=pid_state::NONE;

        return true;
    } else
        return false;
}

bool sys_ptrace( int sc_num, pid_t pid, pid_state *state )
{
    bool ret=true;

    if( state->state==pid_state::NONE ) {
        state->context_state[0]=ptlib_get_argument( pid, 1 ); // request
        state->context_state[1]=ptlib_get_argument( pid, 2 ); // pid
        state->context_state[2]=ptlib_get_argument( pid, 3 ); // addr
        state->context_state[3]=ptlib_get_argument( pid, 4 ); // data

        dlog("ptrace: %d ptrace( %d, "PID_F", %p, %p )\n", pid, state->context_state[0], state->context_state[1], state->context_state[2],
            state->context_state[3] );

        ptlib_set_syscall( pid, PREF_NOP );
        state->state=pid_state::REDIRECT2;
    } else if( state->state==pid_state::REDIRECT2 ) {
        state->state=pid_state::NONE;

        // Let's see what whether we need to succeed
        switch( (int)state->context_state[0] ) {
        case PTRACE_TRACEME:
            if( begin_trace( state->parent, pid ) ) {
                dlog("ptrace: %d PTRACE_TRACEME parent "PID_F"\n", pid, state->parent );
                ptlib_set_retval( pid, 0 );
            } else {
                dlog("ptrace: %d PTRACE_TRACEME failed %s\n", pid, strerror(errno) );
                ptlib_set_error( pid, state->orig_sc, errno );
            }
            break;
        case PTRACE_ATTACH:
            if( begin_trace( pid, (pid_t)state->context_state[1] ) ) {
                dlog("ptrace: %d PTRACE_ATTACH("PID_F") succeeded\n", pid, (pid_t)state->context_state[1] );
                ptlib_set_retval( pid, 0 );
            } else {
                dlog("ptrace: %d PTRACE_ATTACH("PID_F") failed %s\n", pid, (pid_t)state->context_state[1], strerror(errno) );
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
            // We do not support single step right now
            ptlib_set_error( pid, state->orig_sc, EINVAL );
            break;
        case PTRACE_CONT:
        case PTRACE_SYSCALL:
            handle_cont_syscall( pid, state );
            break;
        case PTRACE_KILL:
            break;
        case PTRACE_DETACH:
            handle_detach( pid, state );
            break;
        default:
            dlog("ptrace: "PID_F" Unsupported option %x\n", pid, (int)state->context_state[0] );
            ptlib_set_error(pid, state->orig_sc, EINVAL);
            break;
        }
    }

    return ret;
}
