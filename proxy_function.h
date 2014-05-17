#ifndef PROXY_FUNCTION_H
#define PROXY_FUNCTION_H

#include <semaphore.h>
#include <mutex>

#include "log.h"

class proxy_function {
public:
    class node_base {
        int error;

        struct node_base *next;

        sem_t semaphore;

        node_base( const node_base &rhs ) = delete;
        node_base &operator=( const node_base &rhs ) = delete;

        friend class proxy_function;
    protected:
        virtual void actual_run() = 0;
    public:
        node_base() : error(0), next(nullptr)
        {
            sem_init(&semaphore, false, 0);
        }

        virtual ~node_base()
        {
            ASSERT( next==nullptr );
            sem_destroy(&semaphore);
        }

        node_base *run();
        void wait_done();
    };

    template <typename F>
            class node : public node_base
    {
        const F &function;
    public:
        explicit node( const F &a_function ) : function( a_function )
        {
        }

    protected:
        virtual void actual_run()
        {
            function();
        }
    };

    node_base *get_job_list();

    void submit( node_base *job );

private:
    node_base *m_first = nullptr, *m_last = nullptr;
    std::mutex m_lock;
};

#endif // PROXY_FUNCTION_H
