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
#include "file_lie.h"

#include "parent.h"

void sys_fchownat( int sc_num, pid_t pid, pid_state *state )
{
    auto shared_mem_guard = state->uses_buffers();

    uid_t owner = ptlib::get_argument( pid, 3 );
    uid_t group = ptlib::get_argument( pid, 4 );

    // Turn this into a call to fstatat, so we know what dev:inode to change
    ptlib::set_syscall( pid, ptlib::preferred::FSTATAT );
    // First two arguments are the same for both syscalls
    ptlib::set_argument( pid, 3, state->m_proc_mem->non_shared_addr );

    // The flags argument is 5 on fchownat, 4 on fstatat
    int flags = ptlib::get_argument( pid, 5 );
    ptlib::set_argument( pid, 4, flags );

    state->ptrace_syscall_wait(pid, 0);

    if( !ptlib::success( pid, ptlib::preferred::FSTATAT ) ) {
        shared_mem_guard.unlock();
        // If we failed the fstatat, our error is, most likely, the same as we would for fchownat for root
        state->end_handling();

        return;
    }

    struct stat stat = ptlib::get_stat_result( state->m_pid, state->m_tid, ptlib::preferred::FSTATAT,
            state->m_proc_mem->non_shared_addr );
    shared_mem_guard.unlock();

    auto file_list_lock = file_list::lock();
    file_list::stat_override *override = file_list::get_map( stat );

    if( owner!=uid_t(-1L) )
        override->uid = owner;
    if( group!=gid_t(-1L) )
        override->gid = group;

    // Clear SUID and SGID of file due to ownership change
    override->mode &= ~06000;

    file_list_lock.unlock();

    LOG_D() << "Changing ownership of file "<<override->dev<<":"<<override->inode<<
            " to "<<override->uid<<"."<<override->gid;

    state->end_handling();
}

static void real_stat( int sc_num, pid_t pid, pid_state *state, unsigned int buf_arg )
{
    int_ptr stat_addr = ptlib::get_argument( pid, buf_arg );

    state->ptrace_syscall_wait(pid, 0);

    if( ptlib::success( pid, sc_num ) ) {
        // Check the result to see if we need to lie about this file
        struct stat stat = ptlib::get_stat_result( state->m_pid, state->m_tid, sc_num, stat_addr );
        auto file_list_lock = file_list::lock();
        file_list::stat_override *override = file_list::get_map( stat, false );

        if( override ) {
            file_list::apply( stat, *override );

            ptlib::set_stat_result( state->m_pid, state->m_tid, sc_num, stat_addr, &stat );

            LOG_D() << "Reported false info for stat " << *override;
        }
    }

    state->end_handling();
}

void sys_fstatat( int sc_num, pid_t pid, pid_state *state )
{
    real_stat( sc_num, pid, state, 3 );
}

void sys_stat( int sc_num, pid_t pid, pid_state *state )
{
    real_stat( sc_num, pid, state, 2 );
}
