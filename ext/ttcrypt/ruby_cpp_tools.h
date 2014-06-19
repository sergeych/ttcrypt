/*
 * ruby_cpp_tools.h
 *
 *  Created on: 18 июня 2014 г.
 *      Author: sergeych
 *  Copyright (C) 2014 Thrift, Sergey S. Chernov
 */

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


#ifndef RUBY_CPP_TOOLS_H_
#define RUBY_CPP_TOOLS_H_

#include "byte_buffer.h"
#include "big_integer.h"
using namespace thrift;
using namespace std;

extern "C" {
#include <ruby.h>
#include <ruby/thread.h>
}

typedef VALUE (*ruby_method)(...);

inline byte_buffer value_to_byte_buffer(VALUE val) {
	val = StringValue(val);
	return byte_buffer(RSTRING_PTR(val), RSTRING_LEN(val));
}

inline string value_to_string(VALUE val) {
	val = StringValue(val);
	return string(RSTRING_PTR(val), RSTRING_LEN(val));
}

inline VALUE to_hex_value(const big_integer& value) {
	string s = value.to_string(16);
	return rb_str_new(s.c_str(), s.length());
}

inline VALUE to_value(const byte_buffer& value) {
	return rb_str_new((const char*)value.data().get(), value.size());
}

inline VALUE to_rb_string(const byte_buffer& bb) {
	return rb_str_new((const char*) bb.data().get(), bb.size());
}

inline VALUE to_rb_string(const string& s) {
	return rb_str_new(s.c_str(), s.length());
}

inline VALUE to_rb_sym(const string& s) {
	return ID2SYM(rb_intern(s.c_str()));
}

VALUE ruby_unblock2(const std::function<void*()>& block);

void ruby_unblock(const std::function<void(void)>& block);



#endif /* RUBY_CPP_TOOLS_H_ */
