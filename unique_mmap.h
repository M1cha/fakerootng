#ifndef UNIQUE_MMAP_H
#define UNIQUE_MMAP_H

#include <sys/mman.h>
#include <errno.h>
#include "exceptions.h"

class unique_mmap {
    void *m_memory;
    size_t m_size;

public:
    unique_mmap( const unique_mmap &rhs ) = delete;
    unique_mmap &operator=( const unique_mmap &rhs ) = delete;

    unique_mmap() noexcept : unique_mmap( MAP_FAILED, 0 )
    {
    }

    unique_mmap( void *address, size_t length, const char *exception_message=nullptr ) noexcept :
            m_memory( address ), m_size( length )
    {
        if( m_memory==MAP_FAILED && exception_message )
            throw errno_exception( exception_message );
    }

    unique_mmap( const char *exception_message, int fd, size_t length, off_t offset = 0,
            int prot = PROT_READ|PROT_WRITE, int flags = MAP_SHARED ) :
        unique_mmap( mmap(NULL, length, prot, flags, fd, offset), length, exception_message )
    {
    }

    unique_mmap( int fd, size_t length, off_t offset = 0, int prot = PROT_READ|PROT_WRITE, int flags = MAP_SHARED ) :
        unique_mmap( nullptr, fd, length, offset, prot, flags )
    {
    }

    unique_mmap( unique_mmap &&rhs ) noexcept : m_memory( rhs.m_memory ), m_size( rhs.m_size )
    {
        rhs.m_memory = MAP_FAILED;
        rhs.m_size = 0;
    }

    unique_mmap &operator=( unique_mmap &&rhs )
    {
        reset();

        m_memory = rhs.m_memory;
        m_size = rhs.m_size;

        rhs.m_memory = MAP_FAILED;
        rhs.m_size = 0;

        return *this;
    }

    ~unique_mmap() noexcept
    {
        reset();
    }

    void reset()
    {
        if( m_memory != MAP_FAILED )
            munmap( m_memory, m_size );

        m_memory = MAP_FAILED;
        m_size = 0;
    }

    template<typename T> T *get()
    {
        return static_cast<T*>(m_memory);
    }

    template<typename T> const T *get() const
    {
        return static_cast<const T*>(m_memory);
    }

    size_t size() const
    {
        return m_size;
    }

    operator bool() const
    {
        return m_memory != MAP_FAILED;
    }
};

#endif // UNIQUE_MMAP_H
