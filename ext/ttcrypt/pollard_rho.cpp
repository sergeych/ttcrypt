//
//  pollard_rho.cpp
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

#include "pollard_rho.h"

using namespace thrift;
using namespace std;

inline big_integer rho(const big_integer& n) {
    big_integer divisor;
    auto c = big_integer::random_bits(n.bit_length());
    auto x = big_integer::random_bits(n.bit_length());
    auto xx = x;
    
    if( n.is_even() )
        return 2;
    do {
        x = (((x*x) % n) + c) % n;
        xx = (((xx*xx) % n) + c) % n;
        xx = (((xx*xx) % n) + c) % n;
        divisor = gcd(x - xx, n);
    }
    while( divisor == 1 );
    
    return divisor;
}

void pollard_rho::factor(const big_integer &n) {
    if( n == 1 )
        return;
    if( n.is_prime(repetitions) )
        factors.push_back(n);
    else {
        auto divisor = rho(n);
        factor(divisor);
        factor(n/divisor);
    }
}

vector<big_integer> pollard_rho::factorize(const big_integer &number, int repetitions) {
    pollard_rho pr(number, repetitions);
    return pr.factors;
}

