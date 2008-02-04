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

// Function interface is different - returns an extra bool to signify whether to send a trap after the call
bool sys_execve( int sc_num, pid_t pid, pid_state *state, bool &trap_after_call )
{
    trap_after_call=false;

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

                if( state->trace_mode==TRACE_SYSCALL ) {
                    // We are not in the "NONE" state, but the syscall is over. Tell parent to trap
                    trap_after_call=true;
                }
#endif
            } else {
                dlog("execve: "PID_F" failed with error %s\n", pid, strerror(ptlib_get_error(pid, sc_num)) );
            }
        } else {
            state->state=pid_state::NONE;
            dlog("execve: "PID_F" absorbed dummy SIGTRAP after successful execve\n", pid );
            
            // If the trace mode is not SYSCALL, the post handling will not generate a TRACE. If PTLIB_TRAP_AFTER_EXEC is set,
            // a trace is required, however, even if not in TRACE_SYSCALL
            trap_after_call=true;
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
// 2. The parent is a debugger (we are emulating the entire ptrace interface)
//
// Of course, with PTRACE_TRACEME, it is possible that the process not have a debugee when it
// starts the wait, but does have one by the time wait should return. We therefor emulate the
// entire system call, always :-(
static bool real_wait4( int sc_num, pid_t pid, pid_state *state, pid_t param1, int *param2, int param3, void *param4 )
{
    if( state->state==pid_state::NONE ) {
        state->context_state[0]=(void *)param1; // pid
        state->context_state[1]=param2; // status
        state->context_state[2]=(void *)param3; // options
        state->context_state[3]=param4; // rusage

        dlog("wait4: %d num debugees: %d num children: %d, queue %s\n", pid, state->num_debugees, state->num_children,
                state->waiting_signals.empty()?"is empty":"has signals" );

        // Test whether the (emulated) call should fail
        // XXX This is nowhere near the exhustive tests we need to do. We only aim to emulate strace and ourselves at this point in time
        if( state->num_children!=0 || state->num_debugees!=0 || !state->waiting_signals.empty() ) {
            // Only wait if there was no error
            state->state=pid_state::WAITING;
        } else {
            // Set an ECHILD return code
            state->state=pid_state::REDIRECT2;
            ptlib_set_syscall( pid, PREF_NOP ); // NOP call
            state->context_state[0]=(void *)-ECHILD;
        }
    } else if( state->state==pid_state::REDIRECT2 ) {
        // We may get here under two conditions.
        // Either the wait was performed by us and a NOP was carried out, in which case context_state[0] contains 0 and context_state[1]
        // the desired return code (negative for error)
        // Or 
        // A function substancially similar to wait was carried out, in which case context_state[0] contains 1
        if( sc_num==PREF_NOP ) {
            // Performed NOP - set return codes
            if( ((int)state->context_state[0])>=0 )
                ptlib_set_retval( pid, state->context_state[0] );
            else
                ptlib_set_error( pid, state->orig_sc, -((int)state->context_state[0]) );

            ptlib_set_syscall( pid, state->orig_sc );
        }
        // If an actual wait syscall was carried out, we have no more manipualtions to do

        ptlib_set_syscall( pid, state->orig_sc );
        state->state=pid_state::NONE;
    }

    if( state->state==pid_state::WAITING ) {
        if( !state->waiting_signals.empty() ) {
            // Let's see what was asked for
            pid_t wait_pid=(pid_t)state->context_state[0];
            std::list<pid_state::wait_state>::iterator child=state->waiting_signals.begin();

            if( wait_pid<-1 ) {
                // We are looking for process with session id= -pid
                while( child!=state->waiting_signals.end() && state[child->pid()].session_id!=-wait_pid )
                    ++child;
            } else if( wait_pid==-1 ) {
                // Wait for anything. Just leave child as it is
            } else if( wait_pid==0 ) {
                // Wait for session_id==parent's
                while( child!=state->waiting_signals.end() && state[child->pid()].session_id!=state->session_id )
                    ++child;
            } else {
                // Wait for exact match
                while( child!=state->waiting_signals.end() && child->pid()!=wait_pid )
                    ++child;
            }

            if( child!=state->waiting_signals.end() ) {
                // We have what to report - allow the syscall to return
                
                // Fill in the rusage
                if( state->context_state[3]!=NULL )
                    ptlib_set_mem( pid, &child->usage(), state->context_state[3], sizeof(child->usage()) );

                // Is this a report about a terminated program?
                if( !child->debugonly() )
                {
                    // If the parent never carried out the actual "wait", the child will become a zombie
                    // We turn the syscall into a waitpid with the child's pid explicitly given
                    ptlib_set_syscall( pid, SYS_waitpid );
                    ptlib_set_argument( pid, 1, (void *)child->pid() );
                    ptlib_set_argument( pid, 2, state->context_state[1] );
                    ptlib_set_argument( pid, 3, state->context_state[2] );
                } else {
                    // We need to explicitly set all the arguments
                    if( state->context_state[1]!=NULL )
                        ptlib_set_mem( pid, &child->status(), state->context_state[1], sizeof(child->status()) );

                    ptlib_set_syscall( pid, PREF_NOP );

                    state->context_state[0]=(void *)child->pid();
                }

                state->waiting_signals.erase( child );

                state->state=pid_state::REDIRECT2;
            } else {
                dlog("wait4: "PID_F" hanged in wait for %d\n", pid, wait_pid );
            }
        }
        
        if( state->state==pid_state::WAITING && (((int)state->context_state[2])&WNOHANG)!=0 ) {
            // Client asked never to hang
            state->state=pid_state::REDIRECT2;
            ptlib_set_syscall( pid, PREF_NOP );
            state->context_state[0]=0;
        }
    }

    return state->state!=pid_state::WAITING;
}

bool sys_wait4( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        pid_t param1=(pid_t)ptlib_get_argument(pid, 1); // pid
        int *param2=(int *)ptlib_get_argument(pid, 2); // status
        int param3=(int)ptlib_get_argument(pid, 3); // options
        void *param4=ptlib_get_argument(pid, 4); // rusage

        return real_wait4( sc_num, pid, state, param1, param2, param3, param4 );
    } else {
        return real_wait4( sc_num, pid, state, 0, NULL, 0, NULL );
    }
}

// We just set the variables and let wait4 handle our case
bool sys_waitpid( int sc_num, pid_t pid, pid_state *state )
{
    if( state->state==pid_state::NONE ) {
        pid_t param1=(pid_t)ptlib_get_argument(pid, 1); // pid
        int *param2=(int *)ptlib_get_argument(pid, 2); // status
        int param3=(int)ptlib_get_argument(pid, 3); // options

        return real_wait4( sc_num, pid, state, param1, param2, param3, NULL );
    } else {
        return real_wait4( sc_num, pid, state, 0, NULL, 0, NULL );
    }
}

