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
#include "input_stream.h"

std::istream &operator>>( std::istream &stream, const char &chr )
{
    char c;

    stream>>c;

    if( stream && c!=chr ) {
        stream.setstate( std::istream::failbit );

        if( stream.exceptions() & std::istream::failbit )
            throw std::ios_base::failure("Stream contained different character than expected");
    }

    return stream;
}

std::istream &operator>>( std::istream &stream, const char *token )
{
    while( *token ) {
        stream>>*token;
        token++;
    }

    return stream;
}

std::istream &operator>>( std::istream &stream, const std::string &string )
{
    return stream>>string.c_str();
}
