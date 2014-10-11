//
//  byte_buffer.h
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

#ifndef __zcoin__byte_buffer__
#define __zcoin__byte_buffer__

#include <iostream>
#include <string.h>
#include <memory>
#include "text_utils.h"

using namespace std;
namespace thrift {
    
    typedef unsigned char byte;
    
    /**
     Writable memory-effective autorsizing byte buffer. Implements copy-on-write policy,
     so all instances are independent but share data as long as possible. Actual copying
     takes place only when some instance starts updating. It is safe and effective to pass
     it by value and return as value. Is NOT thread safe!
     */
    class byte_buffer {
        
    private:
        std::shared_ptr<byte> buffer;
        size_t length;
        size_t _capacity;
        
    public:
        /** Creates byte buffer from size first bytes from a given memory area.
         Zero bytes are ok.
         */
        byte_buffer(const void* src, size_t size) : length(size), _capacity(size) {
            byte *dst = new byte[length];
            buffer = std::shared_ptr<byte>(dst);
            memcpy(dst, src, length);
        }
        
        byte_buffer(const char* str) : length(strlen(str)) {
            _capacity = length;
            byte *dst = new byte[length];
            buffer = std::shared_ptr<byte>(dst);
            memcpy(dst, str, length);
        }
        
        byte_buffer(const string& str) : length(str.length()) {
            _capacity = length;
            byte *dst = new byte[length];
            buffer = std::shared_ptr<byte>(dst);
            memcpy(dst, str.c_str(), length);
        }
        
        /**
         Empty constructor
         */
        byte_buffer(size_t size=0) :
        buffer(new byte[size]),
        length(size), _capacity(size)
        {
        }
        
        /** Range constructor. Copies a range of the other buffer. range is inclusive
            e,g. (x,0,1) will extract TWO bytes. Negative indexes mean from the end of the
            source, e.g. (x, -2, -1) returns 2 last elements. Constructs empty buffer if requested
            range is empty or invalid.
         @param source 
         @param from_index index of the first extracted element
         @param to_index index of the last extracred element
         */
        template <class I1,class I2>
        byte_buffer(const byte_buffer& source, I1 from_index, I2 to_index) {
            int from = (int) from_index;
            int to = (int) to_index;
            if( from < 0 ) from = (int) source.size() + from;
            if( to < 0 ) to = (int) source.size() + to;
            if( from < 0 ) from = 0;
            if( to < 0 ) to = 0;
            
            if( from >= to ) {
                // Empty buffer
                _capacity = 32;
                length = 0;
                buffer.reset( new byte[_capacity] );
            }
            else {
                length = to - from + 1;
                _capacity = length;
                buffer.reset(new byte[_capacity]);
                memcpy(buffer.get(), source.buffer.get()+from, length);
            }
        }
        
        template<typename T>
        static byte_buffer pad(T fill, size_t size) {
        	byte_buffer result(size);
            memset( result.data().get(), (int)fill, size);
            return result;
        }
        
        shared_ptr<byte> data() const noexcept {
            return buffer;
        }
        
        size_t size() const { return length; }
        
        size_t capacity() const { return _capacity; }
        
        long use_count() const { return buffer.use_count(); }
        
        /**
         Concatenate buffers
         */
        byte_buffer operator + (const byte_buffer& other) const {
            byte_buffer res(length + other.length);
            memcpy(res.buffer.get(), buffer.get(), length);
            memcpy(res.buffer.get() + length, other.buffer.get(), other.length);
            return res;
        }
        
        /**
         byte access (readonly), same as get(int)
         */
        template<class T>
        byte operator[] (T index) const {
            return at(index);
        }
        
        /**
         byte acces (readonly)
         */
        template<class T>
        byte at(T _index) const {
            int index = (int)_index;
            prepare_index(index);
            return buffer.get()[index];
        }
        
        /**
         byte update. negative indexes (if used) mean offset from the end, e.g. -1 is the
         last item.
         */
        template<class T> byte set(T _index, byte value) {
            int index = (int) _index;
            prepare_index(index);
            ensure_unique_owner();
            return (buffer.get()[index] = value);
        }
        
        /**
         Convert to an ASCII string. Non-ASCII characters are substituted by dots.
         */
        string to_string() const noexcept {
            string res;
            for( size_t i=0; i<length; i++) {
                byte b = buffer.get()[i];
                if( b < ' ' || b > 'z') b = '.';
                res.append(1,(char)b);
            }
            return res;
        }
        
        /**
         XOR this and other byte_buffer which should have the same size().
         
         @return new byte_buffer which is XOR of this and other byte_buffer's.
         */
        byte_buffer operator^(const byte_buffer& other) const {
            if( length != other.length)
                throw length_error(sformat("byte buffers should have same size (my:%d != other:%d)", length, other.length));
            byte_buffer res(length);
            
            const byte* src1 = buffer.get();
            const byte* src2 = other.buffer.get();
            byte* dst = res.buffer.get();
            
            for(size_t i=length; i-- > 0;)
                *dst++ = *src1++ ^ *src2++;
            
            return res;
        }
        
        /**
         Find first occurency of a given value starting from a given point
         @param value to find
         @param start_from starting index, -1 means the last byte
         @return index of value or -1 if not found
         */
        int index_of(byte value,int start_from=0) {
            int i = start_from;
            prepare_index(i);
            while( i < length ) {
                if( buffer.get()[i] == value )
                    return i;
                i++;
            }
            return -1;
        }
        
        string hex(unsigned per_string=24) const {
            string hex;
            size_t n = 0;
            for( unsigned i=0; i < length; i++ ) {
                if( i > 0 ) {
                    hex.append(1,' ');
                    if( ++n % per_string == 0 )
                        hex.append("\n");
                }
                hex.append(sformat("%02x", buffer.get()[i]));
            }
            return hex;
        }
        
        /**
         @return true is buffers have the same size and contents/
         */
        bool operator == (const byte_buffer& other) const noexcept {
            if( other.length != length )
                return false;
            return memcmp(buffer.get(), other.buffer.get(), length) == 0;
        }
        
        /**
         Append one byte to the end of the buffer. Buffer capacity extends as need.
         */
        byte_buffer& append_byte(byte byte_value) {
            ensure_capacity(length + 1);
            buffer.get()[length++] = (byte)byte_value;
            return *this;
        }
        
        /** Append another byte_buffer to this
         */
        byte_buffer& operator += (const byte_buffer& other) noexcept;
        
        class iterator {
        public:
            iterator(const byte_buffer& buffer, size_t index=0) : _buffer(buffer), _index(index) {}
            
            byte operator*() const { return (byte)_buffer[_index]; }
            iterator& operator ++() { _index++;  return *this; }
            bool operator!=(const byte_buffer::iterator& x) const { return x._index != _index; }
            
        private:
            const byte_buffer& _buffer;
            size_t _index;
        };
        
        byte_buffer::iterator begin() const { return byte_buffer::iterator(*this, 0); }
        byte_buffer::iterator end() const { return byte_buffer::iterator(*this, size()); }
        
        /**
         Extract subbufer [from..to] inclusive. Negative indexes means offset
         from the end, e.g. 
        
             x.sub(0, -1) == x
         */
        byte_buffer sub(int from,int to) const {
            prepare_index(from);
            prepare_index(to);
            return byte_buffer(*this, from, to);
        }
        
        static byte_buffer random(size_t length);

    protected:
        shared_ptr<byte> clone_data(size_t new_capacity) const {
            shared_ptr<byte> cloned(new byte[new_capacity]);
            memcpy(cloned.get(), buffer.get(), length);
            return cloned;
        }
        
        void ensure_unique_owner() noexcept {
            if( buffer.use_count() > 1 ) {
                buffer = clone_data(_capacity);
            }
        }
        
        void ensure_capacity(size_t min_capacity) {
            if( _capacity <= min_capacity ) {
                auto new_capacity = ((min_capacity + 63) >> 6) << 6;
                if( new_capacity < 64 )
                    new_capacity = 64;
                buffer = clone_data(new_capacity);
                _capacity = new_capacity;
            }
            else {
                ensure_unique_owner();
            }
        }
        
        int prepare_index(int& index) const noexcept {
            if( index < 0 ) index = (int)length + index;
            if( index < 0 || index > length ) throw length_error("wrong index");
            return index;
        }
    };
    
    /**
     Advance to the next non-space character, unless end of string is found.
     @param src reference to pointer, after this call points to next
     character after first non-space character, if found, otherwise
     points to the end of line.
     @return character or 0;
     */
    char next_non_space_char(const char*& src);
    
    /**
     @return weight of the hexadecimal digit 0-1A-F (case insensitive).
     @throw invalid_argument if the character is not a valid digit
     */
    int hex_digit_value(char hex_digit);
    
    /**
     Convert hexadecimal string into a byte_buffer buffer. All space characters are ignored. Note this
     IS NOT an Intel Hex decoder, just hex notation converter, e.g. 01 A0 -> 0x01 0xa0.
     
     @param hex string with even number of hexadecimal digit, case insensitive.
     @return decoded byte_buffer buffer
     @throws invalid_argument if the given string is not a hex string.
     */
    byte_buffer decode_hex(const string& hex);

    inline bool operator==(const string& str, const byte_buffer& bb) {
        return bb.size() == str.length() && memcmp(bb.data().get(), str.c_str(), bb.size()) == 0;
    }
}



#endif /* defined(__zcoin__byte_buffer__) */
