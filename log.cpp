#include "config.h"

#include <boost/log/core.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>

#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>
#include <iostream>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "log.h"
#include "arch/platform.h"

namespace logging = boost::log;
namespace expr = boost::log::expressions;
namespace ios = boost::iostreams;

static ios::file_descriptor_sink log_file;
static ios::stream_buffer<decltype(log_file)> log_streambuf;

bool init_log( const char * file_name, bool enabled, bool flush )
{
    if( !enabled ) {
        logging::core::get()->set_filter
                (
                 logging::trivial::severity >= logging::trivial::fatal
                );
        return true;
    }

    if( !log_file.is_open() ) {
        int fd = open(file_name, O_WRONLY|O_CREAT|O_APPEND, 0666);
        log_file = std::move( ios::file_descriptor_sink(fd, ios::close_handle) );

        // Allocate a log sink
        typedef logging::sinks::synchronous_sink< logging::sinks::text_ostream_backend > text_sink;
        boost::shared_ptr< text_sink > sink = boost::make_shared< text_sink >();

        // Add a stream to write log to
        log_streambuf.open(log_file);
        sink->locked_backend()->add_stream( boost::make_shared<std::ostream>( &log_streambuf ) );
        sink->locked_backend()->auto_flush(flush);

        logging::add_common_attributes();

        sink->set_formatter
        (
            expr::stream
                // << expr::format_date_time< boost::posix_time::ptime >("TimeStamp", "%H%M%S") << ":"
                << expr::attr< logging::attributes::current_thread_id::value_type >("ThreadID") << ":"
                << expr::attr< logging::trivial::severity_level >("Severity") << ":"
                << expr::message
        );

        // Register the sink in the logging core
        logging::core::get()->add_sink(sink);
    }

    return true;
}

int get_log_fd()
{
    if( log_file.is_open() )
        return log_file.handle();
    else
        return -1;
}

void close_log()
{
    // TODO Implement
}

void flush_log()
{
    logging::core::get()->flush();
}
