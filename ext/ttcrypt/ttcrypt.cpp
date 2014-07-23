/*
  ttcrypt.cpp

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

#include "ttcrypt.h"
#include "sha1.h"
#include "sha256.h"

using namespace thrift;

byte_buffer ttcrypt::sha1(const byte_buffer& data) noexcept {
    byte_buffer res(20);
    sha1::calc(data.data().get(), (int)data.size(), res.data().get() );
    return res;
}

byte_buffer ttcrypt::sha256(const thrift::byte_buffer &data) noexcept {
    byte_buffer res(32);
    sha256_ctx ctx;
    sha256_starts(&ctx);
    sha256_update(&ctx, data.data().get(), (uint32) data.size());
    sha256_finish(&ctx, res.data().get());
    return res;
}

byte_buffer ttcrypt::i2osp(const big_integer& i, size_t block_size) noexcept {
    byte_buffer res = i.to_byte_buffer();
    if( block_size > 0 && res.size() != block_size ) {
        size_t pad_length = block_size - res.size() % block_size;
        if( pad_length > 0 )
            return byte_buffer::pad('\0', pad_length) + res;
    }
    return res;
}
