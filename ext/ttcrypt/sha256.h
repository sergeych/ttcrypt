//
//  sha256.h
//  iGlomp
//
//  Created by Sergey Chernov on 28.10.11.
//  Copyright (c) 2011 Thrift. All rights reserved.
//

#ifndef iGlomp_sha256_h
#define iGlomp_sha256_h

/* Declarations of functions and data types used for SHA256 and SHA224 sum
 library functions.
 Copyright (C) 2005, 2006, 2008, 2009 Free Software Foundation, Inc.
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

typedef unsigned char uint8;
typedef unsigned int uint32;

#ifndef SHA256_H
# define SHA256_H 1

# include <stdio.h>
# include <stdint.h>

# ifdef __cplusplus
extern "C" {
# endif
    
    /* Structure to save state of computation between the single steps.  */
    typedef struct sha256_ctx
    {
        uint32_t state[8];
        
        uint32_t total[2];
        size_t buflen;
        uint8 buffer[64];
    } sha256_context;
    
    enum { SHA224_DIGEST_SIZE = 224 / 8 };
    enum { SHA256_DIGEST_SIZE = 256 / 8 };
    
    void sha256_starts( sha256_context *ctx );
    void sha256_update( sha256_context *ctx, uint8 *input, uint32 length );
    void sha256_finish( sha256_context *ctx, uint8 digest[32] );
    
    
    
# ifdef __cplusplus
}
# endif


#endif
#endif
