//
//  RsaKey.h
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

#ifndef __zcoin__RsaKey__
#define __zcoin__RsaKey__

#include <iostream>
#include <unordered_map>
#include "byte_buffer.h"
#include "big_integer.h"
#include "ttcrypt.h"

namespace ttcrypt {
    
    using namespace thrift;
    
    byte_buffer eme_oaep_encode( const byte_buffer& message,size_t emLen, const byte_buffer* p=0, const byte_buffer *seed=nullptr);
    byte_buffer eme_oaep_decode(const byte_buffer& message,const byte_buffer* p=0);
    
    byte_buffer emsa_pss_encode(const byte_buffer& message,size_t emBits,byte_buffer (*hash)(const byte_buffer&),const byte_buffer* salt);
    bool emsa_pss_verify(const byte_buffer& source_message,
                         const byte_buffer& encoded_message,
                         size_t emBits,
                         byte_buffer (*hash)(const byte_buffer&),
                         size_t debug_sLen=0);
    
    /**
     PKCS#1 v2.2 RSA algorythm (only STRONG encoding e.g. OAEP/PSS, weak 1.5 is NOT supported by purpose!). Full implementation 
     (key generation, construction from parts, encryption, signing).
    */
    class rsa_key {
    public:
        
        class error : public invalid_argument {
        public:
            error(const char* reason) : invalid_argument(reason){}
        };

        /**
         Construct from { {name, value} }  paris, like { { "e", 123 }, { "n":data_n } }. @see #set().
         */
        rsa_key(const std::initializer_list<std::pair<string, big_integer>>& params)
        {
            set_params(params);
        }

        /**
         Construct from any map-like container that provides pair iterator with pair.first
         and pair.second members. @see #set()
         */
        template <class Tmap>
        rsa_key(const Tmap& map)
        {
            set_params(map);
        }
        
        rsa_key()
        {}
        
        /** 
         Set the named parameter to a given value. Supported values are: n, e, d, p, q, dp, dq, qinv.
         Not case sesitive. Call normalize_key() when done changing parameters.
         */
        void set(const string& name, const big_integer& value);
        
        /**
         Construct private key from parts. If not all parts are provided, recalculates missing ones that
         is somewhat slow.
        */
        rsa_key(const big_integer& N, const big_integer& E, const big_integer& P,const big_integer& Q,
                const big_integer& dP=0, const big_integer& dQ=0, const big_integer& qInv=9)
        : n(N), e(E), p(P), q(Q), dp(dP), dq(dQ), q_inv(qInv)
        {
            normalize_key();
        }
        
        /**
         Construct "slow" ptivate key from parts.
         */
        rsa_key(const big_integer& N,const big_integer& E, const big_integer& D) : n(N), e(E), d(D), fast_key(false) {
            normalize_key();
        }

        /**
         Construct public key.
         */
        rsa_key(const big_integer& N,const big_integer& E) : n(N), e(E) { normalize_key(); }
        
        /**
         Test that private key present
         */
        bool is_private() const {
            return (p != 0 && q != 0) || d != 0;
        }
        
        /**
         construct and return public key (strip private component if any)
         */
        rsa_key public_key() const {
            return rsa_key(n,e);
        }
        
        /**
         RSAES-OAEP encrypt a message.
         */
        byte_buffer encrypt(const byte_buffer& plaintext) const {
            return rsaep(eme_oaep_encode(plaintext, byte_size - 1, 0, pseed));
        }
        
        /**
         RSAES-OAEP decrypt a given cipertext. requires private key.
         */
        byte_buffer decrypt(const byte_buffer& ciphertext) const {
            return eme_oaep_decode( rsadp( ciphertext) );
        }

        bool self_test(ostream& os);

        /**
         Create RSASSA-PSS signature for a given message. Requires private key.
         @param message what to sign
         @param hash default to sha256
         @param salt to use with a given salt. By default, uses random salt of maximum available length. When
                     using custom salt, you'll need to provide its length on verification (s_len parameter)
         
         */
        byte_buffer sign(const byte_buffer& message, byte_buffer (*hash)(const byte_buffer&)=sha256, const byte_buffer* salt=0) const {
            return rsasp1(emsa_pss_encode(message, bits_size-1, hash, salt));
        }

        /**
         Verify RSASSA-PSS signature.
         
         @param message message to verify
         @param signature PSS signature of the message
         @param hash sha1, sha256 or other hash function (by default sha256)
         @param s_len if manual salt was used, provide its length. by default, salt uses
                      all available space left.
         @return true if the signature is consistent with the message, false otherwise (message is tampered or the signature
                      is broken)
         */
        bool verify(const byte_buffer& message,
                    const byte_buffer& signature,
                    byte_buffer (*hash)(const byte_buffer&)=sha256,
                    size_t s_len=0) const;
        
        /** :nodoc: set seed to debug OAEP encryption. Please DO NOT use 
         */
        void debug_seed(const byte_buffer& s) {
            pseed = &s;
        }
        
        /**
         @return key size in bits 
         */
        unsigned size_in_bits() const { return bits_size; }
        
        /**
         @return key size in bytes
         */
        unsigned size_in_bytes() const { return byte_size; }
        
        /**
         Generate new key pair of the specified strength. If the system has more than one CPU core,
         use 2 cores to generate key parts.
         @param bits_strength desired strength in bits. it is recommended to use ar least 2048 bits and
                              sizes that are multiplication of 256.
         @param e public exponent, positive integer, this implementation requires it to be prime >= 3.
                  default of 0 uses "good" value 0x10001.
         */
        static rsa_key generate(unsigned bits_strength,size_t e=0);
        
        
        /**
         Update key parameters from map-like container that provides pair iterator with pair.first
         and pair.second members. @see #set()
         */
        template <class Tmap>
        void set_params(const Tmap& map) {
            for( auto pair: map ) {
                set(pair.first, pair.second);
            }
            normalize_key();
        }

        unordered_map<string,big_integer> get_params(bool include_all = false) const noexcept;

        /**
         recalculate parts of the key after chaging it with 
         #set().
         */
        void normalize_key();
        
        /**
         Turn on or off use of blinding algorithm (that repels timing attack) on decrypt and verify
         routines only, as if makes it slower the longer the key is used.
         */
        void use_blinding(bool use) noexcept {
            _use_blinding = use;
        }
        
        byte_buffer get_e() const { return e.to_byte_buffer(); }

    private:
        big_integer n, e, p, q, d, dp, dq, q_inv;
        unsigned byte_size=0, bits_size=0;
        bool fast_key=false, _use_blinding=false;
        
        const byte_buffer *pseed = NULL;
        
        big_integer powmod_sec(const big_integer& x, const big_integer& y, const big_integer& mod) const noexcept {
            return _use_blinding ? ::powmod_sec(x, y, mod) : ::powmod(x, y, mod);
        }
        
        byte_buffer rsaep(const byte_buffer& plaintext) const {
            auto m = os2ip(plaintext);
            require_public_key();
            return i2osp(powmod(m, e, n), byte_size); // Encryption does not need blinding!
        }
        
        void require_public_key() const {
            if( n == 0 || e == 0 )
                throw error("missing public key");
        }
        
        byte_buffer rsasp1(const byte_buffer& m) const;
        byte_buffer rsavp1(const byte_buffer& s) const;
        
        byte_buffer rsadp(const byte_buffer& c) const;
    };
}

#endif /* defined(__zcoin__RsaKey__) */
