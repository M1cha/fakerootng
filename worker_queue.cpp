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

#include <atomic>

#include <assert.h>

#include "log.h"

worker_queue::worker_task::~worker_task()
{
}

worker_queue::worker_queue() : m_terminate(false)
{}

void worker_queue::start()
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
        std::thread *thread = new std::thread( &worker_queue::worker, this );
        m_threads.push_back( std::unique_ptr<std::thread>( thread ) );

        num_threads--;
    }
}

worker_queue::~worker_queue()
{
    std::unique_lock<std::mutex> queue_lock( m_queue_lock );

    ASSERT(m_queue.empty());

    m_terminate=true;
    m_queue_condition.notify_all();

    queue_lock.unlock();

    // Wait for all threads to actually finish
    for( auto &i: m_threads ) {
        i->join();
    }
}

void worker_queue::thread_init()
{
}

void worker_queue::thread_shutdown()
{
}

static std::atomic_uint worker_index;

void worker_queue::worker()
{
    snprintf( logging::thread_name, sizeof(logging::thread_name), "W%u", ++worker_index );

    LOG_I()<<"Worker thread started";
    thread_init();

    while( !m_terminate ) {
        std::unique_lock<std::mutex> queue_lock( m_queue_lock );

        try {
            // Handle all tasks already in the queue
            while( !m_queue.empty() ) {
                std::unique_ptr<worker_task> task( std::move( m_queue.front() ) );
                m_queue.pop_front();

                queue_lock.unlock();

                task->run();

                queue_lock.lock();
            }
        } catch( const std::exception &e )
        {
            LOG_F()<<"Uncaught exception: "<<e.what();
        }
        
        // Wait for more tasks
        if( !m_terminate )
            m_queue_condition.wait(queue_lock);
    }

    thread_shutdown();
    LOG_I()<<"Worker thread shut down";
}

void worker_queue::schedule_task( worker_task * task )
{
    // If the following assert fails, we created the queue but did not call "start".
    ASSERT(m_threads.size()!=0);
    std::unique_lock<std::mutex> queue_lock( m_queue_lock );
    m_queue.push_back( std::unique_ptr<worker_task>(task) );

    m_queue_condition.notify_one();
}
