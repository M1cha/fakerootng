#ifndef DAEMON_H
#define DAEMON_H

#include "exceptions.h"
#include "unique_fd.h"
#include "epoll_event_handlers.h"

#include <list>
#include <string>
#include <unordered_set>
#include <mutex>
#include <thread>
#include <atomic>

class daemonProcess;
class session_fd;
template <class T> class ipcMessage;

// Connect to the daemon, launching it if necessary, and return the connection fd
class daemonCtrl {
    daemonCtrl( const daemonCtrl & )=delete;
    daemonCtrl & operator=( const daemonCtrl & )=delete;

    friend class socket_handler;
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
    explicit session_fd( unique_fd &&fd, socket_handler *handler ) :
        epoll_event_handler( std::move(fd) ), m_handler( handler )
    {
    }

    virtual void handle();

private:
    socket_handler *m_handler;

    void handle_cmd_reserve( const ipcMessage<daemonCtrl::request> &message );
    void handle_cmd_attach( const ipcMessage<daemonCtrl::request> &message );
};

class socket_handler {
    socket_handler( const socket_handler &rhs ) = delete;
    socket_handler &operator=( const socket_handler &rhs ) = delete;
public:
    socket_handler( daemonProcess *daemon, int session_fd ); // Constructor for non-persistent daemon
    // Constructor for persistent daemon
    socket_handler( daemonProcess *daemon, const std::string &path, unique_fd &&state_file, unique_fd &&master_fd );

    void start();

    void debugger_idle();
    bool test_should_exit() const;
private:
    friend class master_socket_fd;
    friend class session_fd;
    size_t num_clients = 0;
    daemonProcess *m_daemonProcess;

    std::unordered_set<boost::intrusive_ptr<session_fd>, epoll_event_handler::hash> session_fds;
    unique_fd epoll_fd;
    std::mutex thread_fds_mutex;

    boost::intrusive_ptr<master_socket_fd> master_socket;

    enum class shutdown_state {
        active,         // Active clients being debugged
        dbg_idle,       // Debugger idle
        both_idle,      // Debugger idle, socket handler going into a wait for new clients
        shutdown        // No debugees. No new clients. Exit
    };
    std::atomic<shutdown_state> state;

    void handle_request( const sigset_t *sigmask );
    static void set_client_sock_options( int fd );

    enum class mask_ops { add, remove };

    void register_session( unique_fd &&fd );
    void unregister_session( int fd );
    void recalc_select_mask( mask_ops op, epoll_event_handler *handler );
    void close_session( session_fd *element );
    // Report when the last client closed connection, cause the session thread to close
    void report_last_client();
};

class daemonProcess {
    daemonProcess( const daemonProcess & )=delete;
    daemonProcess & operator=( const daemonProcess & )=delete;

public:
    ~daemonProcess();

    // Create an anonymous daemon process, returning the connection file descriptor
    static int create( bool nodetach );
    static void create( const char *state_file_path, bool nodetach );

    // Check whether the debugger should wait for more events to arrive
    bool test_should_exit() const
    {
        return sock_handler && sock_handler->test_should_exit();
    }

    void sock_handler_exits();
private:
    std::string state_path;
    unique_fd state_fd;
    std::unique_ptr<socket_handler> sock_handler;
    std::thread sock_handler_thread;
    bool sock_handler_wants_out = false;
    bool sock_handler_done = false;

    static bool daemonize( bool nodetach, int skip_fd1=-1, int skip_fd2=-1 );

    explicit daemonProcess( int session_fd ); // Constructor for non-persistent daemon
    // Constructor for persistent daemon
    daemonProcess( const std::string &path, unique_fd &&state_file, unique_fd &&master_fd );

    void start();

    void cleanup_sock_handler();
};

#endif // DAEMON_H
