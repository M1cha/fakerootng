#ifndef FILE_LIE_H
#define FILE_LIE_H

#include <mutex>
#include <iostream>

#include <sys/stat.h>

// Define functions for mapping the real files on disk to what they should be as far as the fake environment is concerned

namespace file_list {
struct stat_override {
    dev_t dev;
    ino_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    dev_t dev_id;

    bool transient = false;

    explicit stat_override( const struct stat &stat ) :
        dev( stat.st_dev ),
        inode( stat.st_ino ),
        mode( stat.st_mode ),
        uid( stat.st_uid ),
        gid( stat.st_gid ),
        dev_id( stat.st_rdev )
    {
    }
};

std::ostream &operator<< (std::ostream &strm, const stat_override &override);

void apply( struct stat &lhs, const stat_override &rhs );

std::unique_lock<std::mutex> lock();

// Returns the information inside the database about a file with the given dev and inode
// returns "false" if no such file exists
struct stat_override *get_map( dev_t dev, ino_t inode, bool create = true );
struct stat_override *get_map( const struct ::stat &stat, bool create = true );

void set_map( const struct stat_override *stat );

void remove_map( dev_t dev, ino_t inode );
void mark_map_stale( dev_t dev, ino_t inode );

void load_map( std::istream &file );
void save_map( std::ostream &file );

};

#endif // FILE_LIE_H
