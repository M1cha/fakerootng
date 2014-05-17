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

#include "daemon.h"

#include <memory>
#include <iostream>
#include <fstream>
#include <functional>

#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <unistd.h>

#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>

#if HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include "exceptions.h"
#include "arch/platform.h"
#include "log.h"
#include "parent.h"
#include "file_lie.h"

template <class T>
class ipcMessage {
    T _payload;
    unsigned char _ancillary_buffer[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec _iovec;
    struct msghdr _header;
    struct ucred *_credentials;

public:
    ipcMessage() : _credentials(NULL)
    {
        memset( &_payload, 0, sizeof(T) );

        memset( &_header, 0, sizeof(_header) );

        _iovec.iov_base=&_payload;
        _iovec.iov_len=sizeof(T);
        _header.msg_iov=&_iovec;
        _header.msg_iovlen=1;

        _header.msg_control=_ancillary_buffer;
    }

    void recv( int fd )
    {
        _header.msg_controllen=sizeof(_ancillary_buffer);
        ssize_t num_read=recvmsg( fd, &_header, 0 );

        if( num_read<0 )
            throw errno_exception("Read failed");

        // Socket closed?
        if( num_read==0 ) {
            throw daemonCtrl::remote_hangup_exception();
        }

        if( static_cast<unsigned>(num_read)<sizeof(T) ) {
            LOG_E() << "Session " << fd << " produced short read (expected " << sizeof(T) <<
                    ", got " << num_read << ")";
            throw daemonCtrl::short_msg_exception();
        }

        // Extract ancillary data
        _credentials=NULL;
        for( struct cmsghdr *cmsg=CMSG_FIRSTHDR(&_header); cmsg!=NULL; cmsg=CMSG_NXTHDR(&_header, cmsg) ) {
            if( cmsg->cmsg_level==SOL_SOCKET && cmsg->cmsg_type==SCM_CREDENTIALS )
                _credentials=(struct ucred *)CMSG_DATA(cmsg);
        }
    }

    void send( int fd )
    {
        _header.msg_controllen=sizeof(_ancillary_buffer);
        struct cmsghdr *cmsg=CMSG_FIRSTHDR(&_header);
        cmsg->cmsg_level=SOL_SOCKET;
        cmsg->cmsg_type=SCM_CREDENTIALS;
        cmsg->cmsg_len=CMSG_LEN(sizeof(struct ucred));
        _header.msg_controllen=cmsg->cmsg_len;

        _credentials=(struct ucred *)CMSG_DATA(cmsg);
        _credentials->pid=getpid();
        _credentials->uid=getuid();
        _credentials->gid=getgid();

        ssize_t num_written=sendmsg( fd, &_header, 0 );

        if( num_written<0 )
            throw errno_exception("Send failed");

        if( static_cast<unsigned>(num_written)<sizeof(T) ) {
            LOG_E() << "Session " << fd << " produced short send (expected " << sizeof(T) << ", got " <<
                    num_written << ")";
            throw daemonCtrl::short_msg_exception();
        }
    }

    T * operator->() { return &_payload; }
    const T * operator->() const { return &_payload; }

    const struct ucred *credentials() const
    {
        if( _credentials==NULL )
            throw detailed_exception("Credentials not set on message");

        return _credentials;
    }
};

static std::unique_ptr<daemonProcess> daemon_process;

daemonCtrl::daemonCtrl(const char *state_file_path, bool nodetach) : daemon_socket(-1), daemon_pid(0)
{
    if( state_file_path==NULL ) {
        // Anonymous daemon. Always needs to start
        daemon_socket = daemonProcess::create( nodetach );
        set_client_sock_options(daemon_socket);
        cmd_reserve();
    } else {
        connect( state_file_path );
        while( daemon_socket<0 ) {
            daemonProcess::create( state_file_path, nodetach );
            connect( state_file_path );
        }
    }
}

daemonCtrl::~daemonCtrl()
{
    if( daemon_socket>=0 ) {
        close(daemon_socket);
        daemon_socket=-1;
    }
}

void daemonCtrl::connect( const char * state_file_path )
{
    int client_socket=socket( PF_UNIX, SOCK_SEQPACKET, 0 );
    if( client_socket==-1 ) {
        // Couldn't create a socket
        throw errno_exception( "Unix socket creation error" );
    }

    sockaddr_un sa;
    sa.sun_family=AF_UNIX;
    snprintf( sa.sun_path, sizeof(sa.sun_path), "%s.run", state_file_path );

    if( ::connect(client_socket, (const struct sockaddr *) &sa, sizeof(sa) )<0 ) {
        close( client_socket );
        // No daemon running
        return;
    }

    try {
        set_client_sock_options(client_socket);
        daemon_socket=client_socket;

        cmd_reserve();
    } catch( const std::exception &exception ) {
        LOG_E() << "Daemon connect failed: " << exception.what();
        close( client_socket );
        daemon_socket=-1;
        throw;
    } catch( ... ) {
        close( client_socket );
        daemon_socket=-1;
        throw;
    }
}
void daemonCtrl::send_std_cmd( commands command, ipcMessage<response> &response ) const
{
    ipcMessage<request> message;
    message->command=command;
    message.send( daemon_socket );

    response.recv( daemon_socket );

    if( response->command!=command )
        throw detailed_exception( "Response received for different command than request" );

    if( response->result>0 ) {
        errno=response->result;
        throw errno_exception( "Command failed" );
    }
}

void daemonCtrl::set_client_sock_options( int fd )
{
    fcntl( fd, F_SETFD, FD_CLOEXEC );

    int passcred=true;
    setsockopt( fd, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred) ); // XXX Check return type?
}

void daemonCtrl::cmd_reserve()
{
    ipcMessage<response> response;
    send_std_cmd( CMD_RESERVE, response );
    daemon_pid=response.credentials()->pid;
}

void daemonCtrl::cmd_attach()
{
    ipcMessage<response> response;
    try {
#if HAVE_DECL_PR_SET_PTRACER
        // We need to tell the kernel it is okay for the debugger to attach to us
        ASSERT( daemon_pid!=0 );
        prctl( PR_SET_PTRACER, daemon_pid, 0, 0, 0 );
#endif // HAVE_DECL_PR_SET_PTRACER
        send_std_cmd( CMD_ATTACH, response );
    } catch( const std::system_error &exception ) {
        errno=exception.code().value();
        throw errno_exception( "Ptrace attach failed" );
    }
}

socket_handler::socket_handler( int session_fd ) :
    epoll_fd(::epoll_create1(EPOLL_CLOEXEC), "epoll fd creation failed")
{
    unique_fd session(session_fd);
    set_client_sock_options(session_fd);
    register_session( std::move(session) );
}

socket_handler::socket_handler( const std::string &path, unique_fd &&state_file, unique_fd &&master_fd ) :
    epoll_fd(::epoll_create1(EPOLL_CLOEXEC), "epoll fd creation failed"),
    master_socket( new master_socket_fd( std::move(master_fd), this ) )
{
    recalc_select_mask( mask_ops::add, master_socket.get() );
}

void socket_handler::start()
{
    strcpy( logging::thread_name, "SOCK" );
    LOG_I() << "Socket handling thread started";
    while( handle_request( NULL ) || master_socket )
        ;
    LOG_I() << "Socket handling thread finished";

    ASSERT(num_clients == 0);
}

bool socket_handler::test_shutdown( int timeout )
{
    epoll_event event;
    int result=epoll_wait( epoll_fd.get(), &event, 1, timeout);
    return result>0;
}

bool socket_handler::client_sockets() const
{
    return num_clients>0;
}

bool socket_handler::handle_request( const sigset_t *sigmask )
{
    bool ret = !session_fds.empty();
    static const size_t CONCURRENT_EVENTS = 5;
    epoll_event events[CONCURRENT_EVENTS];

    // Wait nothing if we are about to exit, indefinitely if we have reason to stay
    int result=epoll_pwait( epoll_fd.get(), events, CONCURRENT_EVENTS, -1, sigmask );
    if( result<0 )
        return ret;

    ASSERT( size_t(result)<=CONCURRENT_EVENTS );
    for( int i=0; i<result; ++i ) {
        boost::intrusive_ptr<epoll_event_handler>
                ptr( reinterpret_cast<epoll_event_handler *>(events[i].data.ptr) );
        ret = ptr->handle() || ret;
    }

    return ret;
}

void socket_handler::set_client_sock_options( int fd )
{
    daemonCtrl::set_client_sock_options(fd);
    fcntl( fd, F_SETFL, O_NONBLOCK );
}

void socket_handler::register_session( unique_fd &&fd )
{
    LOG_I() << "Added session " << fd.get();

    set_client_sock_options( fd.get() );

    auto i = session_fds.insert( new session_fd(std::move(fd), this) );
    recalc_select_mask( mask_ops::add, i.first->get() );

    num_clients++;
}

void socket_handler::recalc_select_mask( mask_ops op, epoll_event_handler *handler )
{
    ASSERT(epoll_fd);

    int epoll_op;

    switch(op) {
    case mask_ops::add:
        epoll_op = EPOLL_CTL_ADD;
        break;
    case mask_ops::remove:
        epoll_op = EPOLL_CTL_DEL;
        break;
    }

    epoll_event event;
    event.events = EPOLLIN;
    event.data.ptr = handler;

    if( epoll_ctl(epoll_fd.get(), epoll_op, handler->get_fd(), &event )<0 )
        throw errno_exception( "Epoll command failed" );
}

void socket_handler::close_session(session_fd *element )
{
    LOG_I() << "Session " << element->get_fd() << " closed";

    recalc_select_mask( mask_ops::remove, element );
    session_fds.erase(element);

    ASSERT(num_clients>0);
    num_clients--;

    if(num_clients == 0 && !master_socket)
        report_last_client();
}

void socket_handler::report_last_client()
{
    // TODO implement
}

daemonProcess::daemonProcess( int session_fd ) :
    sock_handler( new socket_handler( session_fd ) ),
    sock_handler_thread( std::mem_fn( &socket_handler::start ), sock_handler.get() )
{
}

daemonProcess::daemonProcess( const std::string &path, unique_fd &&state_file, unique_fd &&master_fd ) :
    state_path( path ), state_fd( std::move(state_file) ),
    sock_handler( new socket_handler( path, std::move(state_file), std::move(master_fd) ) ),
    sock_handler_thread( std::mem_fn( &socket_handler::start ), sock_handler.get() )
{
    namespace ios = boost::iostreams;

    ios::file_descriptor_source state_file_handle( state_fd.get(), ios::never_close_handle );
    ios::stream_buffer<decltype(state_file_handle)> state_streambuf(state_file_handle);
    std::istream state_stream(&state_streambuf);

    file_list::load_map( state_stream );
}

daemonProcess::~daemonProcess()
{
    if( state_path.length()>0 ) {
        std::string tmp_path( state_path );
        tmp_path+=".tmp";

        std::ofstream new_state( tmp_path.c_str(), std::ios_base::trunc );
        if( !new_state ) {
            LOG_E() << "Failed to open state file for saving: " << strerror(errno);

            return;
        }
        file_list::save_map( new_state );
        new_state.close();

        if( rename( tmp_path.c_str(), state_path.c_str() )<0 ) {
            LOG_E() << "Rename of temporary file failed: " << strerror(errno);
        }
        unlink((state_path+".run").c_str());
    }
}

int daemonProcess::create( bool nodetach )
{
    int sockets[2]={-1, -1}; // 0 - daemon side, 1 - client side
    if( socketpair( PF_UNIX, SOCK_SEQPACKET, 0, sockets )<0 )
        throw errno_exception("Child socket creation error");

    try {
        if( daemonize( nodetach, sockets[0] ) ) {
            // We are the daemon
            daemon_process=std::unique_ptr<daemonProcess>(new daemonProcess(sockets[0]));
            close(sockets[1]);
            daemon_process->start();
            daemon_process.reset();
            exit(0);
        }

        // We are the "child" (technically - parent)

        // Close the daemon side socket
        close(sockets[0]);
        sockets[0]=-1;
    } catch( ... ) {
        // It is very hard to get C++ wrappers to play nice with the wierd semanitcs of "fork", so we close these
        // manually.
        if( sockets[0]>=0 )
            close( sockets[0] );
        close( sockets[1] );

        throw;
    }

    return sockets[1];
}

void daemonProcess::create( const char *state_file_path, bool nodetach )
{
    // Try to obtain the lock
    unique_fd state_file( ::open( state_file_path, O_CREAT|O_RDWR, 0666 ), "State file open failed" );
    if( !state_file.flock( LOCK_EX|LOCK_NB ) )
        // Someone else is holding the lock
        return;

    // We want to return from this function only after the listening socket already exists and is bound, to avoid a race
    unique_fd master_socket( ::socket( PF_UNIX, SOCK_SEQPACKET, 0 ), "Failed to create master socket" );

    // Make the path canonical
    char *state_realpath=realpath(state_file_path, NULL);
    std::string absolute_state_path(state_realpath);
    free( state_realpath );

    sockaddr_un sa;
    sa.sun_family=AF_UNIX;
    snprintf( sa.sun_path, sizeof(sa.sun_path), "%s.run", absolute_state_path.c_str() );

    // Since we are holding the lock, we know no one else is listening
    unlink( sa.sun_path );
    if( bind( master_socket.get(), (const struct sockaddr *) &sa, sizeof(sa) )<0 )
        throw errno_exception( "Failed to bind master socket" );

    listen( master_socket.get(), 10 );

    // At this point the socket is bound to the correct path on the file system, and is listening. We can safely
    // fork the daemon and return control to the debugee

    if( daemonize( nodetach, state_file.get(), master_socket.get() ) ) {
        // We are the daemon
        daemon_process=std::unique_ptr<daemonProcess>(
                new daemonProcess( absolute_state_path, std::move(state_file), std::move(master_socket) ));
        daemon_process->start();
        daemon_process.reset();
        exit(0);
    }

    // We are the "child" (technically - parent) - nothing more to do
}

bool daemonProcess::daemonize( bool nodetach, int skip_fd1, int skip_fd2 )
{
    logging::flush();
    pid_t debugger=fork();
    if( debugger<0 )
        throw errno_exception("Failed to create debugger process");

    if( debugger!=0 ) {
        // We are the parent, which is actually the child (debugee)
        int status;
        if( waitpid( debugger, &status, 0 )<0 )
            throw errno_exception("waitpid on child failed");

        if( !WIFEXITED(status) || WEXITSTATUS(status)!=0 ) {
            LOG_E() << "Child exit with result " << std::hex << status;
            throw detailed_exception( "Child process exit with error - cannot start daemon" );
        }

        return false;
    }

    // We are the child - we want to be the grandchild
    debugger=fork();
    if( debugger<0 ) {
        LOG_F() << "Failed to fork grandchild: " << strerror(errno);
        _exit(1);
    }

    if( debugger!=0 ) {
        // Still the child - exit without any cleanup
        _exit(0);
    }

    // Set the logging name
    logging::process_name = 'F'; // Fakeroot-ng
    strcpy( logging::thread_name, "D" ); // Debugger

#if STRACE_WAITER
    // Print the debugger's PID and sleep for 10 seconds, allowing external attach with strace before we actually do
    // anything.
    std::cout<<"Debugger pid "<<getpid()<<std::endl;
    sleep(10);
    std::cout<<"Sleep done"<<std::endl;
#endif

    // We are the grandchild - complete the daemonization
    setsid();
    LOG_I() << "Debugger started";

    if( !nodetach ) {
        // Close all open file descriptors except our skip_fds and the debug_log (if it exists)
        // Do not close the file handles, nor chdir to root, if in debug mode. This is so that more debug info
        // come out and that core can be dumped
        int fd=logging::get_fd();

        int fd_limit=getdtablesize();
        for( int i=0; i<fd_limit; ++i ) {
            if( i!=skip_fd1 && i!=skip_fd2 && i!=fd )
                close(i);
        }

        // Re-open the std{in,out,err}
        fd=open("/dev/null", O_RDWR);
        if( fd==0 ) { // Otherwise we somehow failed to close everything
            dup(fd);
            dup(fd);
        }

        // Chdir out of the way
        chdir("/");
    }

    return true;
}

#define GRACE_NEW_CONNECTION_TIMEOUT 3
void daemonProcess::start()
{
    init_debugger( this );

    do {
        LOG_I() << "Debugger init loop";
        process_children( this );
        LOG_I() << "Debugger done";
    } while( sock_handler && sock_handler->test_shutdown(GRACE_NEW_CONNECTION_TIMEOUT*1000) );

    shutdown_debugger();

    LOG_I() << "Daemon done";
}

bool master_socket_fd::handle()
{
    unique_fd connection_fd( ::accept(get_fd(), NULL, NULL) );
    if( !connection_fd ) {
        LOG_W() << "Accept failed: " << strerror(errno);
        return false;
    }

    LOG_D() << "Received new session, socket #" << connection_fd.get();
    m_handler->register_session( std::move(connection_fd) );

    return true;
}

bool session_fd::handle()
{
    // Some of the calls in this function remove a pointer to this. In order for our instance not to be deallocated
    // from under us, we hold a smart pointer to ourselves until the function exits
    boost::intrusive_ptr<session_fd> _this(this);

    ipcMessage<daemonCtrl::request> request;
    LOG_T() << "Request on session " << get_fd();

    try {
        request.recv( get_fd() );

        switch( request->command ) {
        case daemonCtrl::CMD_RESERVE:
            handle_cmd_reserve( request );
            break;
        case daemonCtrl::CMD_ATTACH:
            handle_cmd_attach( request );
            break;
        default:
            LOG_E() << "Session " << get_fd() << " sent unknown command " << request->command;
            m_handler->close_session(this);
            break;
        };
    } catch( const daemonCtrl::remote_hangup_exception &exception ) {
        LOG_E() << "Session " << get_fd() << " hung up";
        m_handler->close_session(this);
    }

    return false;
}

void session_fd::handle_cmd_reserve( const ipcMessage<daemonCtrl::request> &message )
{
    LOG_T() << "Reserving";
    ipcMessage<daemonCtrl::response> response;
    response->command=daemonCtrl::CMD_RESERVE;
    response->result=0;
    response.send( get_fd() );
}

void session_fd::handle_cmd_attach( const ipcMessage<daemonCtrl::request> &message )
{
    LOG_T() << "Attaching";
    ipcMessage<daemonCtrl::response> response;
    response->command=daemonCtrl::CMD_ATTACH;
    try {
        attach_debugger( message.credentials()->pid );
        response->result=0;
    } catch( const std::system_error &exception ) {
        response->result=exception.code().value();
    }

    response.send( get_fd() );
}

