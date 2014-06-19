/*
 * ruby_cpp_tools.cpp
 *
 *  Created on: 18 июня 2014 г.
 *      Author: sergeych
 *  Copyright (C) 2014 Thrift, Sergey S. Chernov
 *
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

#include <iostream>
#include "ruby_cpp_tools.h"

struct unblock_data {
	unblock_data(const std::function<void*()> &_block) :
			block(_block) {
	}
	const std::function<void*()> &block;
	std::exception_ptr exception_ptr = NULL;
};

extern "C" {
static void* unblock_executor(void* ptr) {
	unblock_data *data = (unblock_data*) ptr;
	try {
		return data->block();
	} catch (...) {
		data->exception_ptr = std::current_exception();
	}
	return 0;
}
}

VALUE ruby_unblock2(const std::function<void*()>& block) {
	unblock_data d(block);
	VALUE ret = (VALUE) rb_thread_call_without_gvl(unblock_executor, &d,
	NULL, NULL);

	if (d.exception_ptr)
		std::rethrow_exception(d.exception_ptr);

	return ret;
}

void ruby_unblock(const std::function<void(void)>& block) {
	unblock_data d((std::function<void*()>&) block);
	rb_thread_call_without_gvl(unblock_executor, &d,
	NULL, NULL);

	if (d.exception_ptr)
		std::rethrow_exception(d.exception_ptr);
}



