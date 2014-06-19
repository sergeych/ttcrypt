//
//  big_integer.cpp
//  zcoin
//
//  Created by Sergey Chernov on 10.06.14.
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

#include <stdio.h>
#include <assert.h>
#include "big_integer.h"

namespace thrift {
    
    static byte clear_masks[] = {
        0,      // never used
        0x7F,               // clear only MSB
        0x3F, 0x1F, 0x0F,
        0x07, 0x03,
        0x01                // leave only LSB
    };
    
    big_integer big_integer::random_bits(unsigned int n_bits) {
        // big_integer is BIG ENDIAN, e.g. MSB first
        // so we can generate random sequence and mask out high bits
        unsigned n_bytes = (n_bits + 7) / 8;
        unsigned mask_bits = n_bytes*8 - n_bits;
        assert(mask_bits < 8);
        byte_buffer res = byte_buffer::random(n_bytes);
        if( mask_bits != 0 ) {
            res.set(0, res.at(0) & clear_masks[mask_bits]);
        }
        return big_integer(res);
    }
    
    big_integer big_integer::random_between(const thrift::big_integer &min, const thrift::big_integer &max) {
        auto delta = max - min;
        auto r = big_integer::random_bits(delta.bit_length());
        if( r > delta )
            r = r % delta;
        return min + r;
    }
    
}
