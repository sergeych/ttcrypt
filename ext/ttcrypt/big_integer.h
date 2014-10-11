//
//  big_integer.h
//  zcoin
//
//  Created by Sergey Chernov on 03.06.14.
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

#ifndef zcoin_big_integer_h
#define zcoin_big_integer_h

#include <gmp.h>
#include <string.h>
#include "byte_buffer.h"
#include "common_utils.h"

using namespace std;

namespace thrift {
    

    struct big_divmod_t;
    
    class big_integer {
    public:
        big_integer() {
            //        log_d("def ctor");
            mpz_init(val);
        }
        
        big_integer(long value) {
            //        log_d("long ctor %ld",value);
            mpz_init_set_si(val, value);
        }
        
        ~big_integer() {
            // It can be moved
            if( *((byte*)&val) != 0 )
                mpz_clear(val);
        }
        
        big_integer(const big_integer& x) {
            log_d("copy constructor");
            mpz_init(val);
            mpz_set(val, x.val);
        }
        
        big_integer(big_integer&& x) {
            log_d("move constructor");
            memcpy(&val, &x.val, sizeof(val));
            memset((void*)&x.val, 0, sizeof(val));
        }
        
        /**
         Import from string representation using a given base
         */
        big_integer(const string& string_value,int base=10) {
            mpz_init_set_str(val, string_value.c_str(), base);
        }
        
        /**
         Import from BIG ENDIAN byte array 
         */
        big_integer(const byte_buffer& bytes) {
            mpz_init(val);
            // mpz_import (mpz_t rop, size_t count, int order, size_t size, int endian, size_t nails, const void *op)
            mpz_import(val, bytes.size(), 1, 1, 1, 0, bytes.data().get());
        }
        
        const big_integer& operator=(const big_integer&& x) noexcept {
//            log_d("move assign");
            memcpy(&val, &x.val, sizeof(val));
            memset((void*)&x.val, 0, sizeof(val));
            return *this;
        }
        
        const big_integer& operator=(const big_integer& x) noexcept {
            log_d("copy assign");
            mpz_set(val, x.val);
            return *this;
        }
        
        big_integer operator+(const big_integer& b) const noexcept {
            big_integer res;
            mpz_add(res.val, val, b.val);
            return res;
        }
        
//        big_integer& operator+=(const big_integer& b) noexcept {
//            mpz_add(val, val, b.val);
//            return *this;
//        }
        
        big_integer operator-(const big_integer& b) const noexcept {
            big_integer res;
            mpz_sub(res.val, val, b.val);
            return res;
        }
        
        big_integer operator*(const big_integer& b) const noexcept {
            big_integer res;
            mpz_mul(res.val, val, b.val);
            return res;
        }
        
        big_integer operator/(const big_integer& b) const noexcept {
            big_integer res;
            mpz_fdiv_q(res.val, val, b.val);
            return res;
        }
        
        big_integer operator % (const big_integer& d) const noexcept {
            big_integer res;
            mpz_fdiv_r(res.val, val, d.val);
            return res;
        }
        
        big_integer operator <<(unsigned shift) const noexcept {
            big_integer res;
            mpz_mul_2exp(res.val, val, shift);
            return res;
        }
        
        bool operator==(const big_integer& other) const noexcept {
            return mpz_cmp(val, other.val) == 0;
        }
        
        bool operator==(long other) const noexcept {
            return mpz_cmp_si(val, other) == 0;
        }
        
        bool operator<(const big_integer& other) const noexcept {
            return mpz_cmp(val, other.val) < 0;
        }
        
        bool operator<(long other) const noexcept {
            return mpz_cmp_si(val, other) < 0;
        }
        
        bool is_odd() const noexcept {
            return mpz_odd_p(val);
        }
        
        bool is_even() const noexcept {
            return mpz_even_p(val);
        }
        
        size_t size_in_base(int base) {
            return mpz_sizeinbase(val, base);
        }
        
        big_integer operator-() const noexcept {
            big_integer res;
            mpz_neg(res.val, val);
            return res;
        }
        
        unsigned bit_length() const noexcept {
            return (unsigned)mpz_sizeinbase(val, 2);
        }
        
        string to_string(int base=10) const noexcept {
            size_t length = mpz_sizeinbase(val, base) + 2;
            char *buffer = new char[length];
            mpz_get_str(buffer, base, val);
            string res = string(buffer);
            delete buffer;
            return res;
        }
        
        string hex() const noexcept { return to_string(16); }
        
        long to_long() const noexcept {
            return mpz_get_si(val);
        }

        /**
         Convert to BIE ENDIAN bytes array.
         */
        byte_buffer to_byte_buffer() const noexcept {
        	// Workaround for some Andoid targets
        	if( *this == 0 )
        		return byte_buffer::pad(0, 1);
            size_t count = (mpz_sizeinbase (val, 2) + 7) / 8;
            byte_buffer res = byte_buffer(count);
            size_t count2 = count;
            // mpz_export (void *rop, size_t *countp, int order, size_t size, int endian, size_t nails, const mpz_t op)
            mpz_export( res.data().get(), &count2, 1, 1, 1, 0, val);
            if( count != count2 && count2 != 0 )
                throw logic_error("mpz export logic failed");
            return res;
        }
        
        /**
         Test that *this is probably a prime. 
         @param reps number of Rabin-Miller tests. 25 gives an error probability 2e-50 that is usually
                     sufficient.
         */
        bool is_prime(int reps=25) const noexcept {
            return mpz_probab_prime_p(val, reps) != 0;
        }
        
        /**
         Generate random integer I such as 0 <= I <= 2 ** n_bits. Uses byte_buffer (good) uniform
         random engine.
         */
        static big_integer random_bits(unsigned n_bits);
        
        /**
         Generate random integer in the given INCLUSIVE interval
         */
        static big_integer random_between(const big_integer& min,const big_integer& max);
        
        friend big_integer operator*(int a,const big_integer& b) noexcept;
        friend big_integer pow(const big_integer& x,unsigned long y) noexcept;
        friend big_integer powmod(const big_integer& x,const big_integer& y,const big_integer& mod) noexcept;
        friend big_integer powmod_sec(const big_integer& x,const big_integer& y,const big_integer& mod) noexcept;
        friend big_integer abs(const big_integer& x) noexcept;
        friend big_integer inverse(const big_integer& u,const big_integer& v) noexcept;
        
        friend big_integer lcm(const big_integer& u,const big_integer& v) noexcept;
        friend big_integer gcd(const big_integer& u,const big_integer& v) noexcept;
        
        friend big_integer next_prime(const big_integer& i) noexcept;
        
        friend big_divmod_t divmod(const big_integer& n, const big_integer& d) noexcept;
        
    private:
        mpz_t val;
    };
    
    inline big_integer operator "" _b(const char* str) {
        return big_integer(str, 10);
    }
    
    inline big_integer operator*(int a,const big_integer& b) noexcept {
        big_integer res;
        mpz_mul_si(res.val,b.val, a);
        return res;
    }
    
    inline big_integer pow(const big_integer& x,unsigned long y) noexcept {
        big_integer res;
        mpz_pow_ui(res.val, x.val, y);
        return res;
    }
    
    inline big_integer powmod(const big_integer& x,const big_integer& y,const big_integer& mod) noexcept {
        big_integer res;
        mpz_powm(res.val, x.val, y.val, mod.val);
        return res;
    }
    
    inline big_integer powmod_sec(const big_integer& x,const big_integer& y,const big_integer& mod) noexcept {
        big_integer res;
        mpz_powm_sec(res.val, x.val, y.val, mod.val);
        return res;
    }
    
    
    inline string operator+(const string& str, const big_integer& i) {
        return str + i.to_string();
    }
    
    inline string string_value(const big_integer &x) noexcept {
        return x.to_string();
    }
    
    inline ostream& operator << (ostream& s,const big_integer& value) {
        return s << value.to_string();
    }
    
    inline big_integer inverse(const big_integer& u,const big_integer& v) noexcept {
        big_integer res;
        mpz_invert(res.val, u.val, v.val);
        return res;
    }
    
    inline big_integer lcm(const big_integer& u,const big_integer& v) noexcept {
        big_integer res;
        mpz_lcm(res.val, u.val, v.val);
        return res;
    }
    
    inline big_integer gcd(const big_integer& u,const big_integer& v) noexcept {
        big_integer res;
        mpz_gcd(res.val, u.val, v.val);
        return res;
    }
    
    inline big_integer next_prime(const big_integer& i) noexcept {
        big_integer next;
        mpz_nextprime(next.val, i.val);
        return next;
    }
    
    struct big_divmod_t {
        big_integer q;
        big_integer r;
    };
    
    inline big_divmod_t divmod(const big_integer& n,const big_integer& d) noexcept {
        big_divmod_t result;
        mpz_fdiv_qr(result.q.val, result.r.val, n.val, d.val);
        return result;
    }
}

#endif
