#include "config.h"

#include "../worker_queue.h"

#include <iostream>

#include <pthread.h>
#include <unistd.h>

class waiter : public worker_queue::worker_task
{
public:
    ~waiter()
    {
        std::cout<<"Thread "<<pthread_self()<<" waiter "<<this<<" destructed"<<std::endl;
    }

    void run()
    {
        std::cout<<"Thread "<<pthread_self()<<" waiter "<<this<<" about to sleep"<<std::endl;
        sleep(2);
        std::cout<<"Sleep done on thread "<<pthread_self()<<std::endl;
    }
};

int main( int argc, char *argv[] )
{
    if( argc<2 ) {
        std::cerr<<"Need to supply number of tasks to run"<<std::endl;

        return 1;
    }

    std::cout<<"Start queue"<<std::endl;

    worker_queue queue;
    queue.start();

    std::cout<<"Sleep to allow threads to start"<<std::endl;
    sleep(1);

    int num_tasks=atoi(argv[1]);
    std::cout<<"Running "<<num_tasks<<" tasks"<<std::endl;

    for( int i=0; i<num_tasks; ++i ) {
        waiter *task=new waiter;
        std::cout<<"Scheduling waiter at "<<task<<std::endl;
        queue.schedule_task( task );
    }

    sleep(10);

    std::cout<<"Main exit"<<std::endl;
}
