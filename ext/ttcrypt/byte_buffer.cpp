//
//  byte_buffer.cpp
//  zcoin
//
//  Created by Sergey Chernov on 02.06.14.
//  Copyright (c) 2014 thrift. All rights reserved.
//

/*
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <random>
#include "byte_buffer.h"
#include "common_utils.h"
#include "text_utils.h"

namespace thrift {
    
    char next_non_space_char(const char*& src) {
        char ch;
        while( (ch=*src) != 0 ) {
            src++;
            switch (ch) {
                case ' ': case '\t': case '\n': case '\r':
                    break;
                default:
                    return ch;
            }
        }
        return 0;
    }
    
    int hex_digit_value(char hex_digit) {
        char c = toupper(hex_digit);
        if( c >= 'A' && c <= 'F' )
            return c - 'A' + 10;
        if( c >= '0' && c <= '9' )
            return c - '0';
        throw new invalid_argument(sformat("Invalid hex character %c", c));
    }
    
    byte_buffer decode_hex(const string& hex) {
        const char *ptr = hex.c_str();
        byte_buffer res;
        do {
            char c1 = next_non_space_char(ptr);
            if( !c1 ) break;
            char c2 = next_non_space_char(ptr);
            if( !c2 )
                throw invalid_argument("hex has uneven number of digits");
            res.append_byte( (hex_digit_value(c1) << 4) + hex_digit_value(c2) );
        } while(true);
        return res;
    }
    
    byte_buffer& byte_buffer::operator += (const byte_buffer& other) noexcept {
        ensure_capacity(length + other.length);
        memcpy(buffer.get() + length, other.buffer.get(), other.length);
        length += other.length;
        return *this;
    }
    
    static auto random_engine = std::mt19937_64(std::random_device{}());
    
    byte_buffer byte_buffer::random(size_t size) {
        byte_buffer result(size);
        for(size_t i=0; i<size; i++)
            result.set(i, (byte)random_engine());
        return result;
    }
}

