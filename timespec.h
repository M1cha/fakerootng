#include <time.h>

inline bool operator>=( const struct timespec &lhs, const struct timespec &rhs ) {
    return lhs.tv_sec>rhs.tv_sec || (lhs.tv_sec==rhs.tv_sec && lhs.tv_nsec>=rhs.tv_nsec);
}

inline bool operator==( const struct timespec &lhs, const struct timespec &rhs ) {
    return lhs.tv_sec==rhs.tv_sec && lhs.tv_nsec==rhs.tv_nsec;
}

inline bool operator!=( const struct timespec &lhs, const struct timespec &rhs ) {
    return !(lhs==rhs);
}

inline struct timespec &operator-=( struct timespec &lhs, long rhs ) {
    static const long NS_IN_SEC = 1000000000;
    lhs.tv_sec -= rhs / NS_IN_SEC;
    lhs.tv_nsec -= rhs % NS_IN_SEC;

    if( lhs.tv_nsec<0 ) {
        lhs.tv_sec--;
        lhs.tv_nsec += NS_IN_SEC;
    }

    return lhs;
}
