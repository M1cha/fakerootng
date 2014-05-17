#ifndef ARCH_OS_H
#define ARCH_OS_H

#include <thread>

namespace ptlib {

namespace platform {
    struct process_state;
};

/**
  \ingroup ptlib
  @brief namespace for generic linux implementation

  This namespace contains partial implementation of the ptlib interface suitable for all (or most) Linux hardware
  platforms.
 */
namespace linux {
platform::process_state *get_process_state( pid_t pid, bool create = true );

void init( callback_initiator callback );
void cont( __ptrace_request request, pid_t pid, int signal );
void prepare( pid_t pid );
bool wait( pid_t *pid, int *status, extra_data *data, int async );
long parse_wait( pid_t pid, int status, WAIT_RET *type );
WAIT_RET reinterpret( WAIT_RET prevstate, pid_t pid, int status, long *ret );
int get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len );
int set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len );
int get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen );
int set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr );
ssize_t get_cwd( pid_t pid, char *buffer, size_t buff_size );
ssize_t get_fd( pid_t pid, int fd, char *buffer, size_t buff_size );
void save_state( pid_t pid, void *buffer );
void restore_state( pid_t pid, const void *buffer );
pid_t get_parent( pid_t pid );
long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);
long ptrace(enum __ptrace_request request, pid_t pid, int_ptr addr, int_ptr signal);

extern std::thread::id master_thread;
#define ASSERT_MASTER_THREAD() ASSERT(std::this_thread::get_id()==ptlib::linux::master_thread)
#define ASSERT_SLAVE_THREAD() ASSERT(std::this_thread::get_id()!=ptlib::linux::master_thread)

}; // End of namespace linux
}; // End of namespace ptlib

#endif /* ARCH_OS_H */
