#ifndef PLATFORM_SPECIFIC_INTERNAL_H
#define PLATFORM_SPECIFIC_INTERNAL_H

#include <sys/user.h>

namespace ptlib {
namespace platform {

struct process_state {
    pid_t pid;
    user_regs_struct registers;
    bool dirty = false;

    enum class types {
        amd64, i386, x32
    } type;
};

}; // End of namespace platform
}; // End of namespace ptlib

#endif // PLATFORM_SPECIFIC_INTERNAL_H
