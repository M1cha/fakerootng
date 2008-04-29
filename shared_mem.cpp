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
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <stdio.h>
#include <assert.h>

#include "arch/platform.h"
#include "parent.h"
#include "shared_mem.h"

size_t shared_mem::shared_mem_size(0);

void shared_mem::init_size( size_t size )
{
    assert( shared_mem_size==0 );

    shared_mem_size=size;
}

shared_mem::shared_mem() : data(NULL), mem_next(0), mem_prev(0), us(0)
{
}

shared_mem::shared_mem( void *ptr ) : data(new struct shared_mem::data), mem_next(0), mem_prev(0), us(0)
{
    if( data!=NULL ) {
        data->reference_count=1;
        data->wait_next=0;
        data->wait_prev=0;
        data->local_pointer=((char *)ptr)+ptlib_prepare_memory_len();
    }
}

// Copy constructor and operator=
shared_mem::shared_mem( const shared_mem &rhs ) : data(rhs.data), mem_next(0), mem_prev(0), us(0)
{
    if( data!=NULL )
        data->reference_count++;
}

shared_mem &shared_mem::operator =( const shared_mem &rhs )
{
    release();

    data=rhs.data;
    if( data!=NULL ) {
        data->reference_count++;

        // Link us to the other
        assert(us!=rhs.us || us==0);

        if( us!=0 && rhs.us!=0 ) {
            mem_next=rhs.us;
            mem_prev=rhs.mem_prev;
            pid_state *other_state;

            if( mem_prev!=0 ) {
                other_state=lookup_state( mem_prev );
                assert(other_state!=NULL);
                other_state->shared_mem_local.mem_next=us;
            }

            if( mem_next!=0 ) {
                other_state=lookup_state( mem_next );
                assert( other_state!=NULL && &(other_state->shared_mem_local)==&rhs );
                other_state->shared_mem_local.mem_prev=us;
            }
        }
    }

    return *this;
}

shared_mem::~shared_mem()
{
    release();
}

void shared_mem::release()
{
    if( data && (--data->reference_count)==0 ) {
        munmap( ((char *)data->local_pointer)-ptlib_prepare_memory_len(), shared_mem_size );
        delete data;
    }

    pid_state *other_state;

    // Unlink us from the shared memory resource
    if( mem_next!=0 ) {
        other_state=lookup_state(mem_next);
        assert( other_state!=NULL && other_state->shared_mem_local.mem_prev==us );
        other_state->shared_mem_local.mem_prev=mem_prev;
    }
    if( mem_prev!=0 ) {
        other_state=lookup_state(mem_prev);
        assert( other_state!=NULL && other_state->shared_mem_local.mem_next==us );
        other_state->shared_mem_local.mem_next=mem_next;
    }

    data=NULL;
    mem_next=mem_prev=0;
}
