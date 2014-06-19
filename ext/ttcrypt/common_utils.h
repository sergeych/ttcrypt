//
//  common_utils.h
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

#ifndef zcoin_common_utils_h
#define zcoin_common_utils_h

typedef unsigned char byte;

template<class valueT, class countT>
valueT clear_left_bits(valueT value,countT count) {
    byte bitmask = 0x80;
    for( unsigned bit_no=0; bit_no < count; bit_no++ ) {
        value &= ~bitmask;
        bitmask >>= 1;
    }
    return value;
}


template <class A,class B>
bool operator !=(const A& a,const B& b) {
    return !(a == b);
}

template <class A,class B>
bool operator >(const A& a,const B& b) {
    return !(a < b) && !(a == b);
}

template <class A,class B>
bool operator <=(const A& a,const B& b) {
    return a < b || a == b;
}

template <class A,class B>
bool operator >=(const A& a,const B& b) {
    return !(a < b);
}


#endif
