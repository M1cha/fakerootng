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

#include "syscalls.h"
#include "log.h"

#include "parent.h"

void sys_getuid( int sc_num, pid_state *state )
{
    state->ptrace_syscall_wait(0);
    LOG_D() << "Reporting uid " << state->m_uid;
    ptlib::set_retval( state->m_tid, state->m_uid );
    state->end_handling();
}

void sys_geteuid( int sc_num, pid_state *state )
{
    state->ptrace_syscall_wait(0);
    LOG_D() << "Reporting euid " << state->m_euid;
    ptlib::set_retval( state->m_tid, state->m_euid );
    state->end_handling();
}

void sys_getresuid( int sc_num, pid_state *state )
{
    state->ptrace_syscall_wait(0);
    LOG_D() << "Reporting saved uid " << state->m_suid;
    ptlib::set_retval( state->m_tid, state->m_suid );
    state->end_handling();
}
