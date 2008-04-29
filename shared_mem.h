#ifndef SHARED_MEM_H
#define SHARED_MEM_H

class shared_mem {
    static size_t shared_mem_size; // Size of shared memory allocations

    struct data {
        void *local_pointer;
        int reference_count;
        // Wait list
        pid_t wait_next, wait_prev;
    } *data;

    // Who else shares this memory?
    pid_t mem_next, mem_prev, us;

    void release();

public:
    shared_mem();
    ~shared_mem();
    shared_mem( const shared_mem &rhs );
    explicit shared_mem( void *ptr );
    static void init_size( size_t size );
    shared_mem &operator =( const shared_mem &rhs );

    void *get() { return data!=NULL ? data->local_pointer : NULL; }
    void set_pid( pid_t pid ) { us=pid; }

    // Casts
    operator bool() const { return data!=NULL && data->local_pointer!=NULL; }
};

#endif // SHARED_MEM_H
