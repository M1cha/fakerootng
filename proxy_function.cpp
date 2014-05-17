#include "config.h"

#include "proxy_function.h"

proxy_function::node_base *proxy_function::node_base::run()
{
    errno = 0;

    actual_run();

    error = errno;

    node_base *ret = next;
    next = nullptr;

    sem_post( &semaphore );

    return ret;
}

void proxy_function::node_base::wait_done()
{
    sem_wait( &semaphore );

    errno = error;
}

proxy_function::node_base *proxy_function::get_job_list()
{
    std::unique_lock<std::mutex> guard(m_lock);

    node_base *ret = m_first;
    m_first = nullptr;
    m_last = nullptr;

    return ret;
}

void proxy_function::submit( node_base *job )
{
    {
        // Scope in the queue's lock
        std::unique_lock<std::mutex> guard(m_lock);

        if( m_last==nullptr ) {
            ASSERT( m_first==nullptr );
            m_first = job;
            m_last = job;
        } else {
            m_last->next = job;
            m_last = job;
        }
    }

}
