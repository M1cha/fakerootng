#ifndef UNIQUE_FD_H
#define UNIQUE_FD_H

#include <unistd.h>
#include "exceptions.h"

struct unique_fd {
    int _fd;

    unique_fd( const unique_fd &rhs )=delete;
    unique_fd & operator=( const unique_fd &rhs )=delete;
public:
    explicit unique_fd( int fd=-1 ) : _fd( fd>=0 ? fd : -1 )
    {}

    // Movers
    explicit unique_fd( unique_fd &&rhs )
    {
        _fd=rhs._fd;
        rhs._fd=-1;
    }
    unique_fd & operator=( unique_fd &&rhs )
    {
        _fd=rhs._fd;
        rhs._fd=-1;

        return *this;
    }

    // Destructor
    ~unique_fd()
    {
        if( _fd>=0 )
            if( close(_fd)<0 )
                throw errno_exception( "Close failed" );
    }

    int get() const { return _fd; }

    operator bool() const { return _fd>=0; }
};

#endif // UNIQUE_FD_H
