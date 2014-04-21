#ifndef FILE_LIE_H
#define FILE_LIE_H

#include <mutex>

// Define functions for mapping the real files on disk to what they should be as far as the fake environment is concerned

namespace file_list {
struct stat_override {
    dev_t dev;
    ino_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    dev_t dev_id;
};

struct override_key {
    dev_t dev;
    ino_t inode;

    override_key( dev_t _dev, ino_t _inode ) : dev(_dev), inode(_inode)
    {
    }

    bool operator==( const override_key &rhs ) const { return dev==rhs.dev && inode==rhs.inode; }
};

std::unique_lock<std::mutex> lock();

// Returns the information inside the database about a file with the given dev and inode
// returns "false" if no such file exists
bool get_map( dev_t dev, ino_t inode, struct stat_override *stat );

void set_map( const struct stat_override *stat );

void remove_map( dev_t dev, ino_t inode );

void load_map( FILE *file );
void save_map( FILE *file );

};

#endif // FILE_LIE_H
