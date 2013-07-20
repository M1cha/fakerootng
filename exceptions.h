#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <exception>
#include <errno.h>
#include <string.h>
#include <string>

class errno_exception : public std::exception 
{
    int _errno;
    std::string _context;
public:
    errno_exception( const char * context ) :
        _errno( errno ), _context( context )
    {
        _context+=": ";
        _context+=strerror( _errno );
    }

    const char * what() const throw()
    {
        return _context.c_str();
    }

    int get_error() const throw()
    {
        return _errno;
    }

    const char *get_error_message() const throw()
    {
        return strerror(_errno);
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
