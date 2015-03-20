/*
    Fakeroot Next Generation - run command with fake root privileges
    This program is copyrighted. Copyright information is available at the
    AUTHORS file at the root of the source tree for the fakeroot-ng project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "config.h"

#include <unordered_map>

#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "input_stream.h"

#include "file_lie.h"

namespace file_list {

struct override_key {
    dev_t dev;
    ino_t inode;

    override_key( dev_t _dev, ino_t _inode ) : dev(_dev), inode(_inode)
    {
    }

    explicit override_key( const stat_override &override ) : override_key( override.dev, override.inode )
    {
    }

    explicit override_key( const struct stat &stat ) : override_key( stat.st_dev, stat.st_ino )
    {
    }

    bool operator==( const override_key &rhs ) const { return dev==rhs.dev && inode==rhs.inode; }
};

bool operator==( const override_key &lhs, const stat_override &rhs )
{
    return lhs==override_key(rhs);
}

std::ostream &operator<<( std::ostream &strm, const override_key &key )
{
    return strm<<key.dev<<":"<<key.inode;
}

// Operator to sanity check that the override struct points to the same file as a stat struct
bool operator==( const stat_override &lhs, const struct stat &rhs )
{
    return override_key(lhs)==override_key(rhs) &&
            (lhs.mode&0777) == (rhs.st_mode&0777) &&
            (
                (lhs.mode&S_IFMT) == (rhs.st_mode&S_IFMT) ||
                (
                    (rhs.st_mode&S_IFMT) == S_IFREG &&
                    (
                        (lhs.mode&S_IFMT) == 0 ||
                        (lhs.mode&S_IFMT) == S_IFBLK ||
                        (lhs.mode&S_IFMT) == S_IFCHR
                    )
                )
            );
}

struct db_key_hash {
    size_t operator()(const override_key &key) const { return key.inode + key.dev; };
};

typedef std::unordered_map<const override_key, stat_override, db_key_hash> file_hash;

static file_hash map_hash;
static std::mutex map_mutex;

std::unique_lock<std::mutex> lock()
{
    return std::unique_lock<std::mutex>(map_mutex);
}

std::ostream &operator<< (std::ostream &strm, const stat_override &override)
{
    strm<<override.dev<<":"<<override.inode<<":"<<OCT_FORMAT(override.mode, 4)<<" uid: "<<
            override.uid<<" gid: "<<override.gid;

    if( S_ISBLK(override.mode) || S_ISCHR(override.mode) )
        strm<<" device: "<<(override.dev_id>>8)<<","<<(override.dev_id&0xff);

    return strm;
}

void apply( struct stat &lhs, const stat_override &rhs )
{
    ASSERT( override_key(lhs) == override_key(rhs) );

    lhs.st_mode &= 0777;
    lhs.st_mode |= rhs.mode&(S_IFMT|07000);
    if( (lhs.st_mode & S_IFMT)==0 )
        lhs.st_mode |= S_IFREG;

    lhs.st_uid = rhs.uid;
    lhs.st_gid = rhs.gid;
    lhs.st_rdev = rhs.dev_id;
}

#define ASSERT_LOCKED ASSERT(!map_mutex.try_lock())
struct stat_override *get_map( const struct ::stat &stat, bool create )
{
    ASSERT_LOCKED;

    override_key key(stat);

    auto iter = map_hash.find( key );

    if( iter == map_hash.end() ) {
        if( create )
            return &(map_hash.emplace( key, stat_override(stat) ).first->second);
        else
            return nullptr;
    }

    ASSERT( key == iter->second );
    if( ! (iter->second==stat) ) {
        // The file probably changed outside of fakeroot-ng (or so we hope...)
        // Either way, there is a mismatch between the file on disk and the file in our database.
        // Erase the file from the database and start over.
        LOG_W() << "File "<<key<<" mismatch between the disk and the database - erasing from the database";
        map_hash.erase(iter);

        return get_map( stat, create );
    }

    return &iter->second;
}

void remove_map( dev_t dev, ino_t inode )
{
    file_hash::iterator i(map_hash.find( override_key( dev, inode) ));

    if( i!=map_hash.end() )
        map_hash.erase(i);
}

void load_map( std::istream &file )
{
    struct stat override;

    /* TODO Does it make sense to hold the lock during the entire load process? Then again, there should be
       no contention during that time...
     */

    std::skipws(file);

    auto lock_guard( lock() );

    while( file )
    {
        file >>
                "dev=" >> override.st_dev >>
                ",ino=" >> override.st_ino >>
                ",mode=" >> std::oct >> override.st_mode >> std::dec >>
                ",uid=" >> override.st_uid >>
                ",gid=" >> override.st_gid >>
                ",rdev=" >> override.st_rdev;

        if( file ) {
            if( (S_IFMT & override.st_ino)==0 )
                override.st_ino |= S_IFREG;

            get_map( override, true );
        }
    }
}

void save_map( std::ostream &file )
{
    auto lock_guard( lock() );

    for( auto i : map_hash ) {
        const stat_override override( i.second );
        if( !override.transient ) {
            mode_t mode_mask = ~0L;

            if( S_ISREG(override.mode) )
                mode_mask = ~mode_t(S_IFMT);

            file <<
                    "dev=" << override.dev <<
                    ",ino=" << override.inode <<
                    ",mode=" << "0" << OCT_FORMAT(override.mode & mode_mask, 3) <<
                    ",uid=" << override.uid <<
                    ",gid=" << override.gid <<
                    ",rdev=" << override.dev_id <<
                    "\n";
        }
    }
}

};
