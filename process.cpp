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

        // On some platforms "execve" returns, when successful, with SYS_restart_syscall or some such thing
        state->state=pid_state::REDIRECT2;
        state->context_state[0]=0;
    } else if( state->state==pid_state::REDIRECT2 ) {
        if( state->context_state[0]==0 ) {
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
                state->context_state[0]=(void *)1;
#endif
            } else {
                dlog("execve: "PID_F" failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)) );
            }
        } else {
            // Nothing to do here
            state->state=pid_state::NONE;
        }
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

bool sys_setsid( int sc_num, pid_t pid, pid_state *state )
{
    // We do not do any actual manipulation on the syscall. We just keep track over the process' session ID
    if( state->state==pid_state::NONE ) {
        state->state=pid_state::RETURN;
    } else if( state->state==pid_state::RETURN ) {
        state->state=pid_state::NONE;

        if( ptlib_success( pid, sc_num ) ) {
            state->session_id=pid;
        }
    }

    return true;
}

// This call needs to be emulated under one of two conditions:
// 1. Platform does not support "wait" by parent on a debugged child (PTLIB_PARENT_CAN_WAIT=0)
// 2. The parent is a debugger (we are emulating the entire ptrace interface
bool sys_wait4( int sc_num, pid_t pid, pid_state *state )
{
    dlog("wait4: %d num debugees: %d num children: %d\n", pid, state->num_debugees, state->num_children );
    bool cont=true;

    if( state->state==pid_state::NONE ) {
#if PTLIB_PARENT_CAN_WAIT
        // Parent process can wait, so we only need to emulate the call if the process is a debugger
        if( state->num_debugees==0 ) {
            dlog("wait4: %d Process handled as usual\n", pid );
            state->state=pid_state::RETURN;
        } else
#endif
        {
            state->context_state[0]=ptlib_get_argument(pid, 1); // pid
            state->context_state[1]=ptlib_get_argument(pid, 2); // status
            state->context_state[2]=ptlib_get_argument(pid, 3); // options
            state->context_state[3]=ptlib_get_argument(pid, 4); // rusage
            ptlib_set_syscall( pid, PREF_NOP ); // NOP call

            state->state=pid_state::REDIRECT2;
        }
    } else if( state->state==pid_state::RETURN ) {
        // The call was executed as planned
        state->state=pid_state::NONE;
    } else if( state->state==pid_state::REDIRECT2 ) {
        // Test whether the (emulated) call should fail
        // XXX This is nowhere near the exhustive tests we need to do. We only aim to emulate strace and ourselves at this point in time
        if( state->num_children==0 && state->num_debugees==0 ) {
            ptlib_set_error( pid, state->orig_sc, ECHILD );
        } else {
            // Only wait if there was no error
            state->state=pid_state::WAITING;
            cont=false; // By default we hang in wait for something to report
        }
    }

    if( state->state==pid_state::WAITING ) {
        if( !state->waiting_signals.empty() ) {
            // Let's see what was asked for
            pid_t wait_pid=(pid_t)state->context_state[0];
            std::list<pid_state::wait_state>::iterator child=state->waiting_signals.begin();

            if( wait_pid<-1 ) {
                // We are looking for process with session id= -pid
                while( child!=state->waiting_signals.end() && state[child->pid].session_id!=-wait_pid )
                    ++child;
            } else if( wait_pid==-1 ) {
                // Wait for anything. Just leave child as it is
            } else if( wait_pid==0 ) {
                // Wait for session_id==parent's
                while( child!=state->waiting_signals.end() && state[child->pid].session_id!=state->session_id )
                    ++child;
            } else {
                // Wait for exact match
                while( child!=state->waiting_signals.end() && child->pid!=wait_pid )
                    ++child;
            }

            if( child!=state->waiting_signals.end() ) {
                // We have what to report - allow the syscall to return
                
                // Fill in the status and rusage
                if( state->context_state[2]!=NULL )
                    ptlib_set_mem( pid, &child->status, state->context_state[2], sizeof(child->status) );
                if( state->context_state[3]!=NULL )
                    ptlib_set_mem( pid, &child->usage, state->context_state[3], sizeof(child->usage) );

                ptlib_set_retval( pid, (void *)child->pid );
                state->waiting_signals.erase( child );

                state->state=pid_state::NONE;
                cont=true;
            }
        }
        
        if( !cont && (((int)state->context_state[2])&WNOHANG)!=0 ) {
            // Client asked never to hang
            ptlib_set_retval( pid, 0 );
            cont=true;
        }
    }

    return cont;
}

