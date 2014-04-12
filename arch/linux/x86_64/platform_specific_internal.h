#ifndef PLATFORM_SPECIFIC_INTERNAL_H
#define PLATFORM_SPECIFIC_INTERNAL_H

namespace ptlib {
namespace platform {

struct process_state {
    user_regs_struct registers;
    bool dirty = false;

    enum class types {
        amd64, i386, x32
    } type;

    void post_load(pid_t pid);
    void flush(pid_t pid);
};

}; // End of namespace platform
}; // End of namespace ptlib

#endif // PLATFORM_SPECIFIC_INTERNAL_H
