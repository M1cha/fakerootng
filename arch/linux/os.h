#ifndef ARCH_OS_H
#define ARCH_OS_H

namespace ptlib {

int linux_continue( __ptrace_request request, pid_t pid, int signal );
void linux_prepare( pid_t pid );
int linux_wait( pid_t *pid, int *status, extra_data *data, int async );
long linux_parse_wait( pid_t pid, int status, enum WAIT_RET *type );
int linux_reinterpret( enum WAIT_RET prevstate, pid_t pid, int status, long *ret );
int linux_get_mem( pid_t pid, int_ptr process_ptr, void *local_ptr, size_t len );
int linux_set_mem( pid_t pid, const void *local_ptr, int_ptr process_ptr, size_t len );
int linux_get_string( pid_t pid, int_ptr process_ptr, char *local_ptr, size_t maxlen );
int linux_set_string( pid_t pid, const char *local_ptr, int_ptr process_ptr );
ssize_t linux_get_cwd( pid_t pid, char *buffer, size_t buff_size );
ssize_t linux_get_fd( pid_t pid, int fd, char *buffer, size_t buff_size );
void linux_save_state( pid_t pid, void *buffer );
void linux_restore_state( pid_t pid, const void *buffer );
pid_t linux_get_parent( pid_t pid );
int linux_fork_enter( pid_t pid, int orig_sc, int_ptr process_mem, void *our_mem, void *registers[STATE_SIZE],
        int_ptr context[FORK_CONTEXT_SIZE] );
int linux_fork_exit( pid_t pid, pid_t *newpid, void *registers[STATE_SIZE], int_ptr context[FORK_CONTEXT_SIZE] );

}; // End of namespace ptlib

#endif /* ARCH_OS_H */
