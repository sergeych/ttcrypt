//
//  pollard_rho.h
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

#ifndef __zcoin__pollard_rho__
#define __zcoin__pollard_rho__

#include <iostream>
#include <vector>
#include "big_integer.h"

using namespace std;
namespace thrift {

/**
 Factorize some number
 */
class pollard_rho {
public:
    
    static vector<big_integer> factorize(const big_integer& number, int repetitions = 25);
    
private:
    pollard_rho(const big_integer& number,int repetitions) : repetitions(repetitions) {
        factor(number);
    }
    
    void factor(const big_integer& n);
    
    int repetitions;
    std::vector<big_integer> factors;
};

}

#endif /* defined(__zcoin__pollard_rho__) */
