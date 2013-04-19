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

#include "worker_queue.h"

#include <assert.h>

worker_queue::worker_task::~worker_task()
{
}

worker_queue::worker_queue() : m_terminate(false)
{
    // Run a thread per CPU
    unsigned num_threads=std::thread::hardware_concurrency();
    // Plus one for luck
    num_threads++;

    // No less than two threads, no matter how many (or few) CPUs we have
    if( num_threads<2 )
        num_threads=2;

    // Start up the correct number of threads
    m_threads.reserve( num_threads );
    while( num_threads>0 ) {
        m_threads.push_back( std::unique_ptr<std::thread>( new std::thread( &worker_queue::worker, this ) ) );

        num_threads--;
    }
}

worker_queue::~worker_queue()
{
    std::unique_lock<std::mutex> queue_lock( m_queue_lock );

    assert(m_queue.empty());

    m_terminate=true;
    m_queue_condition.notify_all();

    queue_lock.unlock();

    // Wait for all threads to actually finish
    for( auto &i: m_threads )
        i->join();
}

void worker_queue::worker()
{
    while( !m_terminate ) {
        // Handle all tasks already in the queue
        std::unique_lock<std::mutex> queue_lock( m_queue_lock );
        while( !m_queue.empty() ) {
            std::unique_ptr<worker_task> task( std::move( m_queue.front() ) );
            m_queue.pop_front();

            queue_lock.unlock();

            task->run();

            queue_lock.lock();
        }
        
        // Wait for more tasks
        if( !m_terminate )
            m_queue_condition.wait(queue_lock);
    }
}

void worker_queue::schedule_task( worker_task * task )
{
    std::unique_lock<std::mutex> queue_lock( m_queue_lock );
    m_queue.push_back( std::unique_ptr<worker_task>(task) );

    m_queue_condition.notify_one();
}
