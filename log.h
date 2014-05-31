#ifndef LOG_H
#define LOG_H

#include <iostream>
#include <iomanip>
#include <mutex>

namespace logging {

bool init( const char * file_name, bool enabled, bool flush );
int get_fd();
void close();
void flush();

enum class severity {
    FATAL,
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE
};

static inline std::ostream &operator<< (std::ostream &strm, severity level)
{
#define PRODUCE_CASE(level) case severity::level: strm<<#level; break
    switch( level ) {
        PRODUCE_CASE(FATAL);
        PRODUCE_CASE(ERROR);
        PRODUCE_CASE(WARN);
        PRODUCE_CASE(INFO);
        PRODUCE_CASE(DEBUG);
        PRODUCE_CASE(TRACE);
    }
#undef PRODUCE_CASE

    return strm;
}

extern severity filter_level;
extern bool auto_flush;
extern char process_name;
extern thread_local char thread_name[20];
extern std::ostream *logstream;
extern std::mutex log_lock;

class log_cleanup {
    std::ostream &logstream;
    bool unconditional_flush;
    std::lock_guard<std::mutex> guard;
public:
    log_cleanup( std::ostream *stream, bool flush ) : logstream(*stream), unconditional_flush(flush),
        guard(log_lock)
    {}

    ~log_cleanup()
    {
        if(auto_flush || unconditional_flush)
            logstream<<std::endl;
        else
            logstream<<"\n";
    }
};

}; // namespace logging

#define LOG_LEVEL_HELPER(level, flush) if( logging::filter_level>=logging::severity::level ) \
                                    (logging::log_cleanup(logging::logstream, flush), *logging::logstream) \
                                            << logging::process_name << ":" << logging::thread_name << ":" \
                                            << logging::severity::level << ":"
#define LOG_T() LOG_LEVEL_HELPER(TRACE, false)
#define LOG_D() LOG_LEVEL_HELPER(DEBUG, false)
#define LOG_I() LOG_LEVEL_HELPER(INFO, false)
#define LOG_W() LOG_LEVEL_HELPER(WARN, false)
#define LOG_E() LOG_LEVEL_HELPER(ERROR, false)
#define LOG_F() LOG_LEVEL_HELPER(FATAL, true)

#define TRACEPOINT() LOG_T() << "Trace point " __FILE__ ":" << __LINE__

#define HEX_FORMAT(val, width) std::setw(width) << std::setfill('0') << std::hex << (val) << std::setbase(0)
#define OCT_FORMAT(val, width) std::setw(width) << std::setfill('0') << std::oct << (val) << std::setbase(0)

#ifdef NDEBUG
#define ASSERT(cond)
#else

#define ASSERT(cond) if(!(cond)) { \
    LOG_F()<<"Assertion failed "<<__FILE__<<":"<<__LINE__<<" at "<<__func__<<": " #cond; \
    abort(); \
}

#endif

#endif // LOG_H
