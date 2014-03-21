#include "config.h"

#include <boost/log/core.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/iostreams/device/file_descriptor.hpp>
#include <boost/iostreams/stream.hpp>
#include <iostream>

#include "log.h"
#include "arch/platform.h"

namespace logging = boost::log;
namespace ios = boost::iostreams;

static ios::file_descriptor_sink log_file;
static ios::stream_buffer<decltype(log_file)> log_streambuf;

bool init_log( const char * file_name, bool enabled, bool flush )
{
    if( !enabled ) {
        logging::core::get()->set_logging_enabled(false);
        return true;
    }

    if( !log_file.is_open() ) {
        log_file = std::move( ios::file_descriptor_sink(file_name, std::ios_base::app|std::ios_base::out) );

        // Allocate a log sink
        typedef logging::sinks::synchronous_sink< logging::sinks::text_ostream_backend > text_sink;
        boost::shared_ptr< text_sink > sink = boost::make_shared< text_sink >();

        // Add a stream to write log to
        log_streambuf.open(log_file);
        sink->locked_backend()->add_stream( boost::make_shared<std::ostream>( &log_streambuf ) );
        sink->locked_backend()->auto_flush(flush);

        // Register the sink in the logging core
        logging::core::get()->add_sink(sink);
    }

    return true;
}

void close_log()
{
    // XXX Implement
}

int get_log_fd()
{
    if( log_file.is_open() )
        return log_file.handle();
    else
        return -1;
}
