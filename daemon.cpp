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

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <unistd.h>

#include "exceptions.h"
#include "arch/platform.h"
#include "log.h"
#include "parent.h"

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
            dlog("Session %d produced short read (expected %lu, got %ld)", fd, sizeof(T), num_read);
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
            dlog("Session %d produced short send (expected %lu, got %ld)", fd, sizeof(T), num_written);
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

daemonCtrl::daemonCtrl(const char *state_file_path, bool nodetach) : daemon_socket(-1)
{
    if( state_file_path==NULL ) {
        // Anonymous daemon. Always needs to start
        daemon_socket = daemonProcess::create( nodetach );
        set_client_sock_options(daemon_socket);
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
    } catch( const errno_exception &exception ) {
        dlog("Daemon connect failed: %s (%s)", exception.what(), exception.get_error_message() );
        close( client_socket );
        daemon_socket=-1;
    } catch( const std::exception &exception ) {
        dlog("Daemon connect failed: %s", exception.what());
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
}

void daemonCtrl::cmd_attach()
{
    ipcMessage<response> response;
    try {
        send_std_cmd( CMD_ATTACH, response );
    } catch( const errno_exception &exception ) {
        errno=exception.get_error();
        throw errno_exception( "Ptrace attach failed" );
    }
}

daemonProcess::daemonProcess( int session_fd ) : master_socket(), max_fd(0)
{
    unique_fd session(session_fd);
    set_client_sock_options(session_fd);
    FD_ZERO( &file_set );
    register_session( session );
}

void daemonProcess::register_session( unique_fd &fd )
{
    dlog("Added session %d\n", fd.get());
    session_fds.push_back( std::move(fd) );
    recalc_select_mask();
}

int daemonProcess::create( bool nodetach )
{
    int sockets[2]={-1, -1}; // 0 - daemon side, 1 - client side
    if( socketpair( PF_UNIX, SOCK_SEQPACKET, 0, sockets )<0 )
        throw errno_exception("Child socket creation error");

    try {
        if( daemonize( sockets[0], nodetach ) ) {
            // We are the daemon
            daemon_process=std::unique_ptr<daemonProcess>(new daemonProcess(sockets[0]));
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
    // XXX Needs implementation
}

bool daemonProcess::daemonize( int skip_fd, bool nodetach )
{
    pid_t debugger=fork();
    if( debugger<0 )
        throw errno_exception("Failed to create debugger process");

    if( debugger!=0 ) {
        // We are the parent, which is actually the child (debugee)
        int status;
        if( waitpid( debugger, &status, 0 )<0 )
            throw errno_exception("waitpid on child failed");

        if( !WIFEXITED(status) || WEXITSTATUS(status)!=0 ) {
            dlog("Child exit with result %x", status);
            throw detailed_exception( "Child process exit with error - cannot start daemon" );
        }

        return false;
    }

    // We are the child - we want to be the grandchild
    debugger=fork();
    if( debugger<0 ) {
        dlog("Failed to fork grandchild: %s", strerror(errno));
        _exit(1);
    }

    if( debugger!=0 ) {
        // Still the child - exit without any cleanup
        _exit(0);
    }

    // We are the grandchild - complete the daemonization
    setsid();
    dlog("Debugger started\n");

    if( !nodetach ) {
        // Close all open file descriptors except our skip_fd and the debug_log (if it exists)
        // Do not close the file handles, nor chdir to root, if in debug mode. This is so that more debug info
        // come out and that core can be dumped
        int fd=get_log_fd();

        int fd_limit=getdtablesize();
        for( int i=0; i<fd_limit; ++i ) {
            if( i!=skip_fd && i!=fd )
                close(i);
        }

        // Re-open the std{in,out,err}
        fd=open("/dev/null", O_RDWR);
        if( fd==0 ) { // Otherwise we somehow failed to close everything
            dup(fd);
            dup(fd);
        }

        // Chdir out of the way of everyone
        chdir("/");
    }

    return true;
}

void daemonProcess::start()
{
    do {
        // XXX Logic needs to include timeout on last disconnect
        dlog("Debugger init loop\n");
        process_children( this );
    } while(session_fds.size()>0);
    dlog("Debugger done\n");
}

#define RECONNECT_GRACE 3 // Number of seconds to wait for a reconnection after all sockets ended
bool daemonProcess::handle_request( const sigset_t *sigmask )
{
    bool ret=session_fds.size()>0;
    fd_set read_set=file_set;
    fd_set except_set=file_set;
    struct timespec timeout;
    timeout.tv_sec=RECONNECT_GRACE;
    timeout.tv_nsec=0;
    int result=pselect( max_fd, &read_set, NULL, &except_set, &timeout, sigmask );
    if( result<0 )
        return ret;

    if( master_socket && FD_ISSET( master_socket.get(), &read_set ) ) {
        result--;
        handle_new_connection();
    }

    if( result>=0 ) {
        auto i=session_fds.begin();
        while( i!=session_fds.end() ) {
            auto current=i;
            // handling might erase i, so we make sure to perform the loop increment before everything else
            ++i;

            try {
                if( FD_ISSET( current->get(), &read_set ) || FD_ISSET( current->get(), &except_set ) )
                    handle_connection_request( current );
            } catch( const errno_exception &except ) {
                dlog("Read from session socket %d failed: %s (%s)", current->get(), except.what(),
                        except.get_error_message());
            } catch( const daemonCtrl::terminal_error &except ) {
                close_session(current);
            }
        }
    }

    return ret;
}

void daemonProcess::set_client_sock_options( int fd )
{
    daemonCtrl::set_client_sock_options(fd);
    fcntl( fd, F_SETFL, O_NONBLOCK );
}

void daemonProcess::handle_new_connection()
{
    assert(master_socket);
    unique_fd connection_fd( ::accept( master_socket.get(), NULL, NULL ) );
    if( !connection_fd ) {
        dlog( "Accept failed: %s", strerror(errno) );
        return;
    }

    set_client_sock_options( connection_fd.get() );

    session_fds.push_back(std::move(connection_fd));
    dlog("Received new session, socket #%d", connection_fd.get());
    recalc_select_mask();
}

void daemonProcess::handle_connection_request( decltype(session_fds)::iterator & element )
{
    ipcMessage<daemonCtrl::request> request;

    try {
        request.recv( element->get() );

        switch( request->command ) {
        case daemonCtrl::CMD_RESERVE:
            handle_cmd_reserve( element, request );
            break;
        case daemonCtrl::CMD_ATTACH:
            handle_cmd_attach( element, request );
            break;
        default:
            dlog("Session %d sent unknown command %d\n", element->get(), request->command);
            close_session(element);
        };
    } catch( const daemonCtrl::remote_hangup_exception &exception ) {
        dlog("Session %d hung up\n", element->get());
        close_session(element);
    }
}

void daemonProcess::handle_cmd_reserve( decltype(session_fds)::iterator & element,
        const ipcMessage<daemonCtrl::request> &message )
{
    ipcMessage<daemonCtrl::response> response;
    response->command=daemonCtrl::CMD_RESERVE;
    response->result=0;
    response.send(element->get());
}

void daemonProcess::handle_cmd_attach( decltype(session_fds)::iterator & element,
        const ipcMessage<daemonCtrl::request> &message )
{
    ipcMessage<daemonCtrl::response> response;
    response->command=daemonCtrl::CMD_ATTACH;
    try {
        attach_debugger( message.credentials()->pid );
        response->result=0;
    } catch( const errno_exception &exception ) {
        response->result=exception.get_error();
    }

    response.send(element->get());
}

void daemonProcess::recalc_select_mask()
{
    FD_ZERO(&file_set);
    max_fd=-1;

    for( auto i=session_fds.begin(); i!=session_fds.end(); ++i ) {
        FD_SET(i->get(), &file_set);
        if( i->get()>max_fd )
            max_fd=i->get();
    }

    max_fd++;
}

void daemonProcess::close_session( decltype(session_fds)::iterator & element )
{
    dlog("Session %d closed\n", element->get());
    session_fds.erase(element);

    recalc_select_mask();
}
