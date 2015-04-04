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

#include <signal.h>

#include "syscalls.h"
#include "log.h"
#include "parent.h"

static void perform_syscall( int sc_num, pid_state *state )
{
    state->ptrace_syscall_wait(0);
    state->end_handling();
}

void sys_munmap( int sc_num, pid_state *state )
{
    if( !state->m_proc_mem->shared_ptr ) {
        return perform_syscall(sc_num, state);
    }

    int_ptr low_start, low_end, high_start, high_end;

    // Sort the ranges so we can easily compare them.
    if( state->m_proc_mem->shared_addr < state->m_proc_mem->non_shared_addr ) {
        low_start = state->m_proc_mem->shared_addr - ptlib::prepare_memory_len;
        low_end = low_start + shared_mem_size;

        high_start = state->m_proc_mem->non_shared_addr;
        high_end = high_start + static_mem_size;
    } else {
        low_start = state->m_proc_mem->non_shared_addr;
        low_end = low_start + static_mem_size;

        high_start = state->m_proc_mem->shared_addr - ptlib::prepare_memory_len;
        high_end = high_start + shared_mem_size;
    }

    int_ptr unmap_addr = state->get_argument( 0 );
    size_t unmap_len = state->get_argument( 1 );

    if( unmap_addr>high_end || unmap_addr+unmap_len <= low_start ||
            (unmap_addr>low_end && unmap_addr+unmap_len <= high_start) )
    {
        // fast path: unmap does not overlap our regions - pass it through
        return perform_syscall(sc_num, state);
    }

    // In order to reach this point, application would need to ask to unmap regions it did not mmap to begin with.
    LOG_I()<<state<<" attempted to unmap our memory regions inside it. Attempted to unmap address "<<
            (void *)unmap_addr<<" to "<< (void *)(unmap_addr + unmap_len)<<". Our regions are "<<
            (void *)low_start<<" to "<<(void *)low_end<<" and "<<(void *)high_start<<" to "<<(void *)high_end;
    unsigned num_ranges = 0;
    struct { int_ptr start; size_t len; } ranges[3]; // Maximum 3 ranges
    bool parse_done = false;

    // A couple of helper functions to keep the code clean
    auto push_unmap = [&]( int_ptr addr, size_t length )
    {
        ranges[num_ranges].start = addr;
        ranges[num_ranges].len = length;
        ++num_ranges;
        LOG_D()<<"Pushing unmap region "<<(void *)addr<<" to "<<(void *)(addr+length);
    };
    auto advance_params = [&]( int_ptr new_start )
    {
        ASSERT(new_start > unmap_addr);
        if( parse_done )
            return;

        size_t reduce = new_start - unmap_addr;
        if( reduce >= unmap_len )
            parse_done = true;
        else {
            unmap_addr = new_start;
            unmap_len -= reduce;
        }
    };

    if( unmap_addr<low_start ) {
        push_unmap(unmap_addr, low_start-unmap_addr);
    }

    if( unmap_addr<low_end ) {
        advance_params(low_end);
    }

    if( !parse_done && unmap_addr<high_start ) {
        if( unmap_addr+unmap_len < high_start )
            push_unmap(unmap_addr, unmap_len);
        else
            push_unmap(unmap_addr, high_start-unmap_addr);
    }

    if( unmap_addr<high_end ) {
        advance_params(high_end);
    }

    if( !parse_done ) {
        push_unmap(unmap_addr, unmap_len);
    }

    LOG_I()<<"Split unmap into "<<num_ranges<<" ranges";
    if( num_ranges==0 ) {
        // Requested unmap was entirely contained within our blocks. Naughty!
        LOG_I()<<"unmap region entirely contained within our memory. Turn operation into NOP";

        // XXX Set to NOP
        state->set_syscall( ptlib::preferred::NOP );

        state->ptrace_syscall_wait(0);
        state->set_retval(0);

        state->end_handling();
        return;
    }

    auto mem_guard = state->uses_buffers();
    auto saved_state = state->save_state();
    for( unsigned i=1; i<num_ranges; ++i ) {
        state->set_argument( 0, ranges[num_ranges - i].start );
        state->set_argument( 1, ranges[num_ranges - i].len );

        state->ptrace_syscall_wait(0);
        // XXX Handle failure

        state->generate_syscall();
        state->ptrace_syscall_wait( 0 );
    }

    state->restore_state( &saved_state );
    state->set_argument( 0, ranges[0].start );
    state->set_argument( 1, ranges[0].len );

    state->ptrace_syscall_wait(0);

    state->end_handling();
}

void sys_mmap( int sc_num, pid_state *state )
{
    if( !state->m_proc_mem->shared_ptr ) {
        return perform_syscall(sc_num, state);
    }

    int_ptr mmap_addr = state->get_argument( 0 );
    size_t mmap_len = state->get_argument( 1 );
    int mmap_flags = state->get_argument( 3 );

    if( (mmap_flags & MAP_FIXED)==0 )
        // Not a request for a fixed address - the call is okay
        return perform_syscall(sc_num, state);

    int_ptr low_start, low_end, high_start, high_end;

    // Sort the ranges so we can easily compare them.
    if( state->m_proc_mem->shared_addr < state->m_proc_mem->non_shared_addr ) {
        low_start = state->m_proc_mem->shared_addr - ptlib::prepare_memory_len;
        low_end = low_start + shared_mem_size;

        high_start = state->m_proc_mem->non_shared_addr;
        high_end = high_start + static_mem_size;
    } else {
        low_start = state->m_proc_mem->non_shared_addr;
        low_end = low_start + static_mem_size;

        high_start = state->m_proc_mem->shared_addr - ptlib::prepare_memory_len;
        high_end = high_start + shared_mem_size;
    }

    if( mmap_addr>high_end || mmap_addr+mmap_len <= low_start ||
            (mmap_addr>low_end && mmap_addr+mmap_len <= high_start) )
    {
        // fast path: unmap does not overlap our regions - pass it through
        return perform_syscall(sc_num, state);
    }

    // The process is trying to mmap over our memory regions
    LOG_W()<<"Process "<<state<<" tried to mmap over our memory regions. This is a capital offense. "
            "The process has been killed";

    state->set_syscall(ptlib::preferred::NOP);

    state->ptrace_syscall_wait(0);
    state->terminate();
}
