#ifndef WORKER_QUEUE_H
#define WORKER_QUEUE_H

#include <condition_variable>
#include <vector>
#include <memory>
#include <thread>
#include <deque>

class worker_queue {
    worker_queue( const worker_queue & )=delete;
    worker_queue &operator=( const worker_queue & )=delete;

public:
    class worker_task {
    public:
        virtual ~worker_task();

        virtual void run()=0;
    };

private:
    bool m_terminate;
    std::vector<std::unique_ptr<std::thread>> m_threads;

    std::mutex m_queue_lock;
    std::condition_variable m_queue_condition;
    std::deque<std::unique_ptr<worker_task>> m_queue;

public:
    worker_queue();
    virtual ~worker_queue();

    void schedule_task( worker_task * task ); // register_task will free the task when it is done

protected:
    // Custom code to run in the main thread's context
    virtual void setup_thread( const std::thread::id thread );
    virtual void tear_down_thread( const std::thread::id thread );

    // Custom code to run in the new thread's context
    virtual void thread_init();
    virtual void thread_shutdown();

private:
    void worker();
};

#endif // WORKER_QUEUE_H
