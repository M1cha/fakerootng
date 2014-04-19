#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <system_error>
#include <errno.h>
#include <string.h>
#include <string>

class errno_exception : public std::system_error 
{
public:
    explicit errno_exception( const char * context ) :
        std::system_error( errno, std::system_category(), context )
    {
    }
};

class detailed_exception : public std::exception
{
    const char * _message;
public:
    detailed_exception( const char * message ) : _message( message )
    {}

    const char * what() const throw()
    {
        return _message;
    }
};

#endif // EXCEPTIONS_H
