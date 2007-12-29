#ifndef FILE_LIE_H
#define FILE_LIE_H

// Define functions for mapping the real files on disk to what they should be as far as the fake environment is concerned

#include "arch/platform.h"

struct stat_override {
    dev_t dev;
    ptlib_inode_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    dev_t dev_id;
};

// Returns the information inside the database about a file with the given dev and inode
// returns "false" if no such file exists
bool get_map( dev_t dev, ptlib_inode_t inode, struct stat_override *stat );

void set_map( const struct stat_override *stat );

#endif // FILE_LIE_H
