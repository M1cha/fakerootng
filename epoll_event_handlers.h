#ifndef EPOLL_EVENT_HANDLERS_H
#define EPOLL_EVENT_HANDLERS_H

#include <boost/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include "unique_fd.h"

class epoll_event_handler : public boost::intrusive_ref_counter<epoll_event_handler> {
public:
    epoll_event_handler( const epoll_event_handler &rhs ) = delete;
    epoll_event_handler &operator=( const epoll_event_handler &rhs ) = delete;

    explicit epoll_event_handler( unique_fd &&fd ) : m_fd(std::move(fd))
    {}

    virtual ~epoll_event_handler()
    {}

    virtual void handle() = 0;

    int get_fd() const
    {
        return m_fd.get();
    }

    struct hash {
        size_t operator()(const epoll_event_handler &key) const
        {
            return key.get_fd();
        }
        size_t operator()(const epoll_event_handler *key) const
        {
            return (*this)(*key);
        }
        size_t operator()(const boost::intrusive_ptr<epoll_event_handler> &key) const
        {
            return (*this)(*key);
        }
    };

    struct equal_to {
        bool operator()( const epoll_event_handler &lhs, const epoll_event_handler &rhs ) const
        {
            return lhs.get_fd() == rhs.get_fd();
        }
        bool operator()( const epoll_event_handler *lhs, const epoll_event_handler *rhs ) const
        {
            return (*this)(*lhs, *rhs);
        }
        bool operator()( const boost::intrusive_ptr<epoll_event_handler> &lhs,
                const boost::intrusive_ptr<epoll_event_handler> &rhs ) const
        {
            return (*this)(*lhs, *rhs);
        }
    };
private:
    unique_fd m_fd;
};

class socket_handler;

class master_socket_fd : public epoll_event_handler
{
public:
    explicit master_socket_fd( unique_fd &&fd, socket_handler *handler ) :
        epoll_event_handler( std::move(fd) ), m_handler( handler )
    {
    }

    virtual void handle();

private:
    socket_handler *m_handler;
};

#endif // EPOLL_EVENT_HANDLERS_H
