#ifndef DAEMON_H
#define DAEMON_H

#include "exceptions.h"
#include "unique_fd.h"
#include "epoll_event_handlers.h"

#include <list>
#include <string>
#include <unordered_set>
#include <mutex>

class daemonProcess;
class session_fd;
template <class T> class ipcMessage;

// Connect to the daemon, launching it if necessary, and return the connection fd
class daemonCtrl {
    daemonCtrl( const daemonCtrl & )=delete;
    daemonCtrl & operator=( const daemonCtrl & )=delete;

    friend class daemonProcess;
    friend class session_fd;

    enum commands {
        CMD_RESERVE,
        CMD_ATTACH
    };

    struct request {
        enum commands command;
    };

    struct response {
        enum commands command;
        int result;
    };
public:
    class terminal_error : public detailed_exception {
    public:
        terminal_error( const char * msg ) : detailed_exception(msg)
        {
        }
    };

    class remote_hangup_exception : public terminal_error {
    public:
        remote_hangup_exception() : terminal_error( "Remote hung up" )
        {}
    };

    class short_msg_exception : public terminal_error {
    public:
        short_msg_exception() : terminal_error( "Remote sent short message" )
        {}
    };

private:
    int daemon_socket;
    pid_t daemon_pid;

public:
    daemonCtrl(const char *state_file_path, bool nodetach);
    ~daemonCtrl();

    void cmd_attach();
private:
    void connect( const char * state_file_path );
    // Standard commands are commands with no reply other than "ACK"
    void send_std_cmd( commands command, ipcMessage<response> &response ) const;

    static void set_client_sock_options( int fd );

    void cmd_reserve();
};

class session_fd : public epoll_event_handler
{
public:
    explicit session_fd( unique_fd &&fd, daemonProcess *daemon ) :
        epoll_event_handler( std::move(fd) ), m_daemon( daemon )
    {
    }

    virtual bool handle();

private:
    daemonProcess *m_daemon;

    void handle_cmd_reserve( const ipcMessage<daemonCtrl::request> &message );
    void handle_cmd_attach( const ipcMessage<daemonCtrl::request> &message );
};

class daemonProcess {
    friend class master_socket_fd;
    friend class session_fd;

    daemonProcess( const daemonProcess & )=delete;
    daemonProcess & operator=( const daemonProcess & )=delete;

    std::unordered_set<boost::intrusive_ptr<session_fd>, epoll_event_handler::hash> session_fds;
    unique_fd epoll_fd;
    std::list<boost::intrusive_ptr<thread_fd>> thread_fds;
    std::mutex thread_fds_mutex;

    std::string state_path;
    boost::intrusive_ptr<master_socket_fd> master_socket;
    unique_fd state_fd;
    pthread_t master_thread;

    static bool daemonize( bool nodetach, int skip_fd1=-1, int skip_fd2=-1 );

    explicit daemonProcess( int session_fd ); // Constructor for non-persistent daemon
    // Constructor for persistent daemon
    daemonProcess( const std::string &path, unique_fd &&state_file, unique_fd &&master_fd );

public:
    ~daemonProcess();

    // Create an anonymous daemon process, returning the connection file descriptor
    static int create( bool nodetach );
    static void create( const char *state_file_path, bool nodetach );

    bool handle_request( const sigset_t *sigmask, bool existing_children );
    static void set_client_sock_options( int fd );

    void register_thread_socket( int fd );
    void unregister_thread_socket( int fd );
private:
    enum class mask_ops { add, remove };

    void start();
    void register_session( unique_fd &&fd );
    void unregister_session( int fd );
    void recalc_select_mask( mask_ops op, epoll_event_handler *handler );
    void close_session( session_fd *element );
};

#endif // DAEMON_H
