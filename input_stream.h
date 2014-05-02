#ifndef INPUT_STREAM_H

#include <istream>
#include <string>

// Scanf type input operators. Consume relevant characters from input stream and
// don't store them anywhere.
std::istream &operator>>( std::istream &stream, const char &chr );
std::istream &operator>>( std::istream &stream, const char *string );
std::istream &operator>>( std::istream &stream, const std::string &string );

#define INPUT_STREAM_H
#endif // INPUT_STREAM_H
