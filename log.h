#ifndef LOG_H
#define LOG_H

#include <boost/log/trivial.hpp>
#include <iomanip>

bool init_log( const char * file_name, bool enabled, bool flush );
int get_log_fd();
void close_log();
void flush_log();

#define LOG_T() BOOST_LOG_TRIVIAL(trace)
#define LOG_D() BOOST_LOG_TRIVIAL(debug)
#define LOG_I() BOOST_LOG_TRIVIAL(info)
#define LOG_W() BOOST_LOG_TRIVIAL(warning)
#define LOG_E() BOOST_LOG_TRIVIAL(error)
#define LOG_F() BOOST_LOG_TRIVIAL(fatal)

#define HEX_FORMAT(val, width) std::setw(width) << std::setfill('0') << std::hex << (val) << std::setbase(0)

#ifdef NDEBUG
#define ASSERT(cond)
#else

#define ASSERT(cond) if(!(cond)) { \
    LOG_F()<<"Assertion failed "<<__FILE__<<":"<<__LINE__<<" at "<<__func__<<": " #cond; \
    flush_log(); \
}

#endif

#endif // LOG_H
