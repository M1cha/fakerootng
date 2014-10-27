#include "config.h"
#include "log.h"

#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>
#include <iostream>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

namespace ios = boost::iostreams;

namespace logging {

static ios::file_descriptor_sink log_file;
static ios::stream_buffer<decltype(log_file)> log_streambuf;

severity filter_level;
bool auto_flush;
char process_name;
thread_local char thread_name[20];
std::ostream *logstream;
std::mutex log_lock;

bool init( const char * file_name, bool enabled, bool flush, severity level )
{
    filter_level = level;

    if( !enabled ) {
        logstream = &std::cerr;
        return true;
    }

    if( !log_file.is_open() ) {
        int fd = open(file_name, O_WRONLY|O_CREAT|O_APPEND, 0666);
        log_file = std::move( ios::file_descriptor_sink(fd, ios::close_handle) );

        // Add a stream to write log to
        log_streambuf.open(log_file);
        logstream = new std::ostream( &log_streambuf );
        auto_flush = flush;

        process_name = 'C';
        strcpy( thread_name, "M" );
    }

    return true;
}

int get_fd()
{
    if( log_file.is_open() )
        return log_file.handle();
    else
        return -1;
}

void close()
{
    // TODO Implement
    flush();
}

void flush()
{
    std::flush( *logstream );
}

}; // namespace logging
