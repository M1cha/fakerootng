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

template <class ID_T> static void real_get_id( int sc_num, pid_state *state, ID_T result )
{
    state->ptrace_syscall_wait(0);
    state->set_retval( result );
    state->end_handling();
}

void sys_getuid( int sc_num, pid_state *state )
{
    LOG_D() << state << " Reporting uid " << state->m_uid;
    real_get_id( sc_num, state, state->m_uid );
}

void sys_geteuid( int sc_num, pid_state *state )
{
    LOG_D() << state << " Reporting euid " << state->m_euid;
    real_get_id( sc_num, state, state->m_euid );
}

void sys_getgid( int sc_num, pid_state *state )
{
    LOG_D() << state << " Reporting gid " << state->m_gid;
    real_get_id( sc_num, state, state->m_gid );
}

void sys_getegid( int sc_num, pid_state *state )
{
    LOG_D() << state << " Reporting egid " << state->m_egid;
    real_get_id( sc_num, state, state->m_egid );
}

template <class ID_T>
static void real_getres_id( int sc_num, pid_state *state, const char *name, ID_T id, ID_T eid, ID_T sid )
{
    LOG_D() << "Reporting " << name << " " << state->m_uid << " e" << name << " " << state->m_euid << " s" << name <<
            " " << state->m_suid;

    state->set_syscall( ptlib::preferred::NOP );
    state->ptrace_syscall_wait( 0 );

    // XXX Add checking for valid address space
    state->set_mem( &id, state->get_argument(0), sizeof( id ) );
    state->set_mem( &eid, state->get_argument(1), sizeof( eid ) );
    state->set_mem( &sid, state->get_argument(2), sizeof( sid ) );

    state->set_retval( 0 );

    state->end_handling();
}

void sys_getresuid( int sc_num, pid_state *state )
{
    real_getres_id<uid_t>( sc_num, state, "uid", state->m_uid, state->m_euid, state->m_suid );
}

void sys_getresuid16( int sc_num, pid_state *state )
{
    real_getres_id<uint16_t>( sc_num, state, "uid", state->m_uid, state->m_euid, state->m_suid );
}

void sys_getresgid( int sc_num, pid_state *state )
{
    real_getres_id<gid_t>( sc_num, state, "gid", state->m_gid, state->m_egid, state->m_sgid );
}

void sys_getresgid16( int sc_num, pid_state *state )
{
    real_getres_id<uint16_t>( sc_num, state, "gid", state->m_gid, state->m_egid, state->m_sgid );
}
