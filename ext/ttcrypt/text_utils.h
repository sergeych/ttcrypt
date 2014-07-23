//
//  text_utils.h
//  zcoin
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

#ifndef __zcoin__text_utils__
#define __zcoin__text_utils__

#include <iostream>
#include <memory>

std::string sformat(const std::string fmt_str, ...);
std::string vsformat(const std::string fmt_str, va_list args);

#ifdef DEBUG

template <class T> void log_d(const T& object,const std::string& msg) {
    std::cout << (object.to_string() + ": " + msg) << std::endl;
}

template <class T> void log_d(T *const object,const std::string& msg) {
    log_d(*object, msg);
}

inline void log_d(const std::string format, ...) {
    va_list ap;
    va_start(ap, format);
    std::cout << vsformat(format, ap) << std::endl;
    va_end(ap);
}

#else

#define log_d(...)

#endif

template <class T>
void stopwatch(T text, std::function<void(void)> block) {
    std::cout << "Starting " << text << "...";
    std::cout.flush();
    clock_t start = clock();
    block();
    std::cout << " done, " << (clock() - start)/1000.0 << "ms " << std::endl;
}

#endif /* defined(__zcoin__text_utils__) */
