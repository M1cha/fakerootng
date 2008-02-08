#ifndef ARCH_OS_H
#define ARCH_OS_H

int ptlib_linux_continue( int request, pid_t pid, int signal );
void ptlib_linux_prepare( pid_t pid );
int ptlib_linux_wait( pid_t *pid, int *status, ptlib_extra_data *data );
long ptlib_linux_parse_wait( pid_t pid, int status, enum PTLIB_WAIT_RET *type );
int ptlib_linux_reinterpret( enum PTLIB_WAIT_RET prevstate, pid_t pid, int status, long *ret );
int ptlib_linux_get_mem( pid_t pid, void *process_ptr, void *local_ptr, size_t len );
int ptlib_linux_set_mem( pid_t pid, const void *local_ptr, void *process_ptr, size_t len );
int ptlib_linux_get_string( pid_t pid, void *process_ptr, char *local_ptr, size_t maxlen );
int ptlib_linux_set_string( pid_t pid, const char *local_ptr, void *process_ptr );

#endif /* ARCH_OS_H */
