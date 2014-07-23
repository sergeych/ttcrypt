//
//  text_utils.cpp
//
//  Created by Sergey Chernov on 01.06.14.
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

#include "text_utils.h"

template<typename X>
X ABS(X val) {
	return val < 0 ? -val : val;
}

std::string sformat(const std::string fmt_str, ...) {
    int final_n, n = ((int)fmt_str.size()) * 2; /* reserve 2 times as much as the length of the fmt_str */
    std::string str;
    std::unique_ptr<char[]> formatted;
    va_list ap;
    while(1) {
        formatted.reset(new char[n]); /* wrap the plain char array into the unique_ptr */
        //        strcpy(&formatted[0], fmt_str.c_str());
        va_start(ap, fmt_str);
        final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
        va_end(ap);
        if (final_n < 0 || final_n >= n)
            n += ABS(final_n - n + 1);
        else
            break;
    }
    return std::string(formatted.get());
}

std::string vsformat(const std::string fmt_str, va_list args) {
    int final_n, n = ((int)fmt_str.size()) * 2; /* reserve 2 times as much as the length of the fmt_str */
    std::string str;
    std::unique_ptr<char[]> formatted;
    while(1) {
        formatted.reset(new char[n]); /* wrap the plain char array into the unique_ptr */
        //        strcpy(&formatted[0], fmt_str.c_str());
        va_list c;
        va_copy(c, args);
        final_n = vsnprintf(&formatted[0], n-1, fmt_str.c_str(), c);
        va_end(c);
        if (final_n < 0 || final_n >= n)
            n += ABS(final_n - n + 1);
        else
            break;
    }
    return std::string(formatted.get());
}

