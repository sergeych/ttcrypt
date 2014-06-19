/*
  ttcrypt.h
  zcoin

  Created by Sergey Chernov on 03.06.14.
  Copyright (c) 2014 thrift. All rights reserved.

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

#ifndef __zcoin__ttcrypt__
#define __zcoin__ttcrypt__

#include <iostream>
#include "byte_buffer.h"
#include "big_integer.h"

using namespace thrift;

namespace ttcrypt {

    byte_buffer sha1(const byte_buffer& data) noexcept;
    byte_buffer sha256(const byte_buffer& data) noexcept;
    
    byte_buffer i2osp(const big_integer& i, size_t block_size=0) noexcept;
    
    inline big_integer os2ip(const byte_buffer& buffer) noexcept {
        return big_integer(buffer);
    }

}


#endif /* defined(__zcoin__ttcrypt__) */
