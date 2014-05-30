#include "../lockless_event.h"

#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <iostream>
#include <thread>

#include <assert.h>

std::atomic_int signals, jobs;
bool done = false;

int handled_signals, handled_jobs;

lockless_event event;

void sigusr_handler(int signum)
{
    event.signal_from_sighandler();
}

void handler()
{
    signal( SIGUSR1, sigusr_handler );

    try {
        while(!done) {
            int num1, num2;

            num1 = signals.exchange(0);
            handled_signals += num1;

            num2 = jobs.exchange(0);
            handled_jobs += num2;

            if( num1==0 && num2==0 )
                std::cout<<"Spurious wakeup\n";

            event.wait();
        }
    } catch( const std::exception &e )
    {
        std::cerr<<"Master thread exit with exception: "<<e.what()<<"\n";

        return;
    }

    std::cout<<"Master thread exit cleanly\n";
}

void send_jobs()
{
    std::cout<<"Thread sending 100000 jobs\n";
    for( int i=0; i<100000; ++i ) {
        ++jobs;

        event.signal();
    }
    std::cout<<"Thread finished sending 10000 jobs\n";
}

int main()
{
    std::thread master( handler );
    std::cout<<"CPU should be idle for 3 seconds"<<std::endl;
    sleep(3);
    std::cout<<"Sending 10000 signal requests\n";
    for( int i=0; i<10000; ++i ) {
        ++signals;
        pthread_kill(master.native_handle(), SIGUSR1);
    }

    std::cout<<"Finished sending 10000 signals. Sleep for 1 second\n";
    sleep(1);
    std::cout<<"Sent 10000 signal request. Counter shows "<<handled_signals<<" \n";
    assert(handled_signals==10000);
    handled_signals=0;

    std::cout<<"Starting 3 threads to send jobs while signaling\n";
    std::thread threads[3];
    for( int i=0; i<3; ++i )
        threads[i]=std::thread(send_jobs);

    for( int i=0; i<100000; ++i ) {
        ++signals;
        pthread_kill(master.native_handle(), SIGUSR1);
    }

    std::cout<<"Waiting for threads to finish\n";
    for( int i=0; i<3; ++i )
        threads[i].join();

    std::cout<<"Sent 300000 jobs and 100000 signal request. Counter shows "<<handled_jobs<<" jobs and "<<handled_signals
            <<" signals \n";

    std::cout<<"Setting done flag to true\n";
    done = true;
    std::cout<<"Waking thread for exit\n";
    event.signal();

    std::cout<<"Waiting for thread to actually exit\n";
    master.join();
    std::cout<<"Main thread exit cleanly\n";

    std::cout<<"After exit: Counter shows "<<handled_jobs<<" jobs and "<<handled_signals
            <<" signals \n";
    return 0;
}
