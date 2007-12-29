#include "config.h"

#include <ext/hash_map>

#include <sys/types.h>
#include <unistd.h>

#include "file_lie.h"

struct db_key {
    dev_t dev;
    ptlib_inode_t inode;

    db_key() : dev(0), inode(0)
    {
    }
    db_key( dev_t _dev, ino_t _inode ) : dev(_dev), inode(_inode)
    {
    }

    bool operator==( const db_key &rhs ) const { return dev==rhs.dev && inode==rhs.inode; }
};

struct db_key_hash {
    size_t operator()(const db_key &key) const { return key.inode; };
};

typedef __gnu_cxx::hash_map<db_key, stat_override, db_key_hash> file_hash;

static file_hash map_hash;

bool get_map( dev_t dev, ptlib_inode_t inode, stat_override *stat )
{
    file_hash::iterator i(map_hash.find( db_key( dev, inode) ));

    if( i!=map_hash.end() ) {
        *stat=i->second;
        return true;
    } else {
        return false;
    }
}

void set_map( const stat_override *stat )
{
    map_hash[db_key(stat->dev, stat->inode)]=*stat;
}
