#ifndef LOG_H
#define LOG_H

#include <boost/log/trivial.hpp>
#include <iomanip>

bool init_log( const char * file_name, bool enabled, bool flush );
int get_log_fd();
void close_log();
void flush_log();

#if 0
#define LOG_FILE_LOC <<__FILE__<<":"<<__LINE__<<":"
#else
#define LOG_FILE_LOC
#endif

#define LOG_T() BOOST_LOG_TRIVIAL(trace) <<__FILE__<<":"<<__LINE__<<":"
#define LOG_D() BOOST_LOG_TRIVIAL(debug) LOG_FILE_LOC
#define LOG_I() BOOST_LOG_TRIVIAL(info) LOG_FILE_LOC
#define LOG_W() BOOST_LOG_TRIVIAL(warning) LOG_FILE_LOC
#define LOG_E() BOOST_LOG_TRIVIAL(error) LOG_FILE_LOC
#define LOG_F() BOOST_LOG_TRIVIAL(fatal) LOG_FILE_LOC

#define HEX_FORMAT(val, width) std::setw(width) << std::setfill('0') << std::hex << (val) << std::setbase(0)
#define OCT_FORMAT(val, width) std::setw(width) << std::setfill('0') << std::oct << (val) << std::setbase(0)

#ifdef NDEBUG
#define ASSERT(cond)
#else

#define ASSERT(cond) if(!(cond)) { \
    LOG_F()<<"Assertion failed "<<__FILE__<<":"<<__LINE__<<" at "<<__func__<<": " #cond; \
    flush_log(); \
    abort(); \
}

#endif

#endif // LOG_H
