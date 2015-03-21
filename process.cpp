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

#include <string.h>

#include <sys/types.h>
#include <signal.h>

#include "syscalls.h"
#include "parent.h"
#include "log.h"

#include "arch/platform.h"

// XXX
// Not implemented functions:
// acct

void sys_fork( int sc_num, pid_t pid, pid_state *state )
{
    LOG_F() << "Fork is unhandled at this point in time. Failing the syscall";
    // TODO unhandled system call. Just report failure for now
    ptlib::set_syscall( pid, ptlib::preferred::NOP );
    state->ptrace_syscall_wait( pid, 0 );
    ptlib::set_error( pid, sc_num, ENOSYS );
    state->end_handling();
}

#if defined(SYS_clone)
void sys_clone( int sc_num, pid_t pid, pid_state *state )
{
    int_ptr flags = ptlib::get_argument( pid, 1 );

#if 0 // Dormant code
    if( (flags&(CLONE_PARENT|CLONE_THREAD))!=0 )
        state->context_state[0]|=NEW_PROCESS_SAME_PARENT;
    if( (flags&CLONE_FS)!=0 )
        state->context_state[0]|=NEW_PROCESS_SAME_ROOT;
    if( (flags&CLONE_FILES)!=0 )
        state->context_state[0]|=NEW_PROCESS_SAME_FD;
    if( (flags&CLONE_VM)!=0 )
        state->context_state[0]|=NEW_PROCESS_SAME_VM;
    if( (flags&CLONE_PTRACE)!=0 )
        state->context_state[0]|=NEW_PROCESS_SAME_DEBUGGER;
#endif

    LOG_T() << pid << ": clone called with flags " << HEX_FORMAT(flags, 8);

    // We do not support containers. If one of the containers related flags was set, fail the call.
    if( flags & (CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS) ) {
        ptlib::set_syscall( pid, ptlib::preferred::NOP );
        state->ptrace_syscall_wait( pid, 0 );
        // Emulate kernel not supporting containers (which, in a way, is what this is)
        ptlib::set_error( pid, sc_num, EINVAL );
        state->end_handling();

        return;
    }

    // Whatever it originally was, add a CLONE_PTRACE to the flags so that we remain in control
    flags|=CLONE_PTRACE;
    flags&=~CLONE_UNTRACED; // Reset the UNTRACED flag

    ptlib::set_argument( pid, 1, flags );
    state->ptrace_syscall_wait(pid, 0);

    if( ptlib::success( pid, sc_num ) ) {
        pid_t newpid=(pid_t)ptlib::get_retval( pid );
        LOG_T() << pid << ": clone succeeded, new process " << newpid;
        unsigned long hnp_flags = 0;
        if( flags&CLONE_VM )
            hnp_flags |= PROC_FLAGS_SAMEVM;
        if( (flags&CSIGNAL) != SIGCHLD )
            hnp_flags |= PROC_FLAGS_CUSTOM_NOTIFY_PARENT;
        if( flags&CLONE_THREAD )
            hnp_flags |= PROC_FLAGS_THREAD;

        pid_t parent = pid;
        if( (flags&CLONE_PARENT) || (flags&CLONE_THREAD) )
            parent = state->m_ppid;

        handle_new_process( newpid, parent, hnp_flags, state );
    } else {
        LOG_T() << pid << ": clone failed: " << strerror( ptlib::get_error( pid, sc_num ) );
    }

    state->end_handling();
}
#endif // SYS_CLONE

void sys_execve( int sc_num, pid_t pid, pid_state *state )
{
    state->ptrace_syscall_wait(pid, 0);
    if( ptlib::success( pid, sc_num ) ) {
        state->reset_memory();
        // If the syscall succeeded, we will get an extra SIGTRAP that would, otherwise, confuse our state keeping
        state->ptrace_syscall_wait(pid, 0);
    }
    state->end_handling();
}
