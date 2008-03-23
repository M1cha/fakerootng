#ifndef CHROOT_H
#define CHROOT_H

#include <string>

struct pid_state;

bool chroot_is_chrooted( const pid_state *state );

// translate a process relative path into a path that is correct outside of the process
// "path" must be in a writable buffer, and its content will be scratch by the function
// "wd" is the directory in relation to which relative paths should be interpreted
// "stat" is going to be filled in with the detail of the last element of the path returned
// If there is some error (say - file not found) stat->st_ino will be equal -1 and errno
// will be set
// If there was no error, but no stat was necessary, stat->st_ino will be equal -2
std::string chroot_parse_path( const pid_state *state, char *path, const std::string &wd, struct stat *stat );

// Same as above, only grab the work directory and file name from the process' state
std::string chroot_translate_param( pid_t pid, const pid_state *state, struct stat *stat, void *process_ptr );

#endif // CHROOT_H
