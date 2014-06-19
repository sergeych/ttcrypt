/*
 * TTcrypt ruby bindings
 *
 * Copyright (C) 2014 Thrift, Sergey S. Chernov

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
#include <stdlib.h>

#include "ruby_cpp_tools.h"

#include "byte_buffer.h"
#include "pollard_rho.h"
#include "rsa_key.h"

extern "C" {
#include <ruby.h>
#include <ruby/thread.h>

void Init_ttcrypt(void);
}

using namespace thrift;
using namespace ttcrypt;

using namespace std;

static VALUE rsa_exception;
static VALUE rsa_class;

VALUE wrap_exceptions(const std::function<VALUE()>& block) {
	try {
		return block();
	} catch (const rsa_key::error& e) {
		rb_raise(rsa_exception, "%s", e.what());
	} catch (const std::exception& e) {
		rb_raise(rb_eStandardError, "%s", e.what());
	} catch (...) {
		rb_raise(rsa_exception, "unknown exception");
	}
	return Qnil;
}

rsa_key* rsa_ptr(VALUE self) {
	rsa_key *pkey;
	Data_Get_Struct(self, rsa_key, pkey);
	return pkey;
}

rsa_key& rsa(VALUE self) {
	return *rsa_ptr(self);
}

extern "C" {

static VALUE rsa_generate(VALUE self, VALUE length) {
	return wrap_exceptions([=] {
		unsigned l = NUM2UINT(length);
		rsa_key *pkey = rsa_ptr(self);
		ruby_unblock([=] {*pkey = rsa_key::generate(l);});
		return self;
	});
}

static VALUE rsa_bits(VALUE self) {
	return INT2NUM(rsa(self).size_in_bits());
}

static VALUE rsa_encrypt(VALUE self, VALUE rb_data) {
	return wrap_exceptions([=] {
		byte_buffer res;
		auto data = value_to_byte_buffer(rb_data);
		ruby_unblock([&] {
					res = rsa(self).encrypt(data);
				});
		return to_rb_string(res);
	});
}

static VALUE rsa_decrypt(VALUE self, VALUE rb_data) {
	return wrap_exceptions([=] {
		byte_buffer res;
		rsa_key& key = rsa(self);
		auto data = value_to_byte_buffer(rb_data);
		ruby_unblock([&res,&data,&key] {
					res = key.decrypt(data);
				});
		return to_rb_string(res);
	});
}

static VALUE factorize(VALUE self, VALUE composite) {
	return wrap_exceptions([=] {
		string s = value_to_string(composite);

		vector<big_integer> factors;
		ruby_unblock([s,&factors] {
					factors = pollard_rho::factorize(decode_hex(s));
				});

		VALUE result = rb_ary_new();
		for (auto factor : factors) {
			rb_ary_push(result, to_hex_value(factor));
		}
		return result;
	});
}

typedef byte_buffer (*hash_t)(const byte_buffer &);

static hash_t hash_provider(VALUE name) {
	string n = value_to_string(name);
	if (n == "sha256")
		return sha256;
	else if (n == "sha1")
		return sha1;
	else
		throw invalid_argument("not supported hash: " + n);
}

static VALUE rsa_sign(VALUE self, VALUE message, VALUE signature_method) {
	return wrap_exceptions([=] {
		byte_buffer m = value_to_byte_buffer(message);
		byte_buffer res;
		hash_t hash = hash_provider(signature_method);

		ruby_unblock([&] {
					res = rsa(self).sign(m, hash);
				});

		return to_value(res);
	});
}

static VALUE rsa_verify(VALUE self, VALUE message, VALUE signature,
		VALUE signature_method) {
	return wrap_exceptions([=] {
		byte_buffer m = value_to_byte_buffer(message);
		byte_buffer s = value_to_byte_buffer(signature);
		bool res;
		hash_t hash = hash_provider(signature_method);

		ruby_unblock([&] {
					res = rsa(self).verify(m, s, hash);
				});

		return res ? Qtrue : Qfalse;
	});
}

static VALUE rsa_extract_public(VALUE self) {
	return wrap_exceptions([=] {
		rsa_key &me = rsa(self);
		VALUE res = rb_class_new_instance(0,NULL,rsa_class);
		rsa_key &pub = rsa(res);
		pub = me.public_key();
		return res;
	});
}

static VALUE rsa_components(VALUE self) {
	return wrap_exceptions([=] {
		rsa_key& key = rsa(self);
		VALUE hash = rb_hash_new();
		for(auto x: key.get_params()) {
			rb_hash_aset(hash,to_rb_sym(x.first),to_rb_string(x.second.to_byte_buffer()));
		}
		return hash;
	});
}

static int do_set_param(VALUE key,VALUE data,VALUE obj) {
	rsa(obj).set(value_to_string(key), value_to_byte_buffer(data));
	return ST_CONTINUE;
}

static VALUE rsa_set_params(VALUE self,VALUE hash) {
	return wrap_exceptions([=]{
		rb_hash_foreach(hash, (int (*)(...)) do_set_param, self);
		rsa(self).normalize_key();
		return Qnil;
	});
}

static VALUE rsa_is_private(VALUE self) {
	return rsa(self).is_private() ? Qtrue : Qfalse;
}

static void rsa_free(void* ptr) {
	delete (ttcrypt::rsa_key*) ptr;
}

static VALUE rsa_alloc(VALUE klass) {
	return Data_Wrap_Struct(klass, 0, rsa_free, new ttcrypt::rsa_key);
}

}

void Init_ttcrypt(void) {

	VALUE ttcrypt_module = rb_define_module("TTcrypt");

	rb_define_method(ttcrypt_module, "_factorize", (ruby_method) factorize, 1);

	rsa_class = rb_define_class_under(ttcrypt_module, "RsaKey", rb_cObject);
	rb_define_alloc_func(rsa_class, rsa_alloc);
	rb_define_method(rsa_class, "_generate", (ruby_method) rsa_generate, 1);
	rb_define_method(rsa_class, "_bits", (ruby_method) rsa_bits, 0);
	rb_define_method(rsa_class, "_encrypt", (ruby_method) rsa_encrypt, 1);
	rb_define_method(rsa_class, "_decrypt", (ruby_method) rsa_decrypt, 1);
	rb_define_method(rsa_class, "_sign", (ruby_method) rsa_sign, 2);
	rb_define_method(rsa_class, "_verify", (ruby_method) rsa_verify, 3);
	rb_define_method(rsa_class, "extract_public",
			(ruby_method) rsa_extract_public, 0);
	rb_define_method(rsa_class, "_is_private", (ruby_method) rsa_is_private, 0);
	rb_define_method(rsa_class, "_components", (ruby_method) rsa_components, 0);
	rb_define_method(rsa_class, "_set_params", (ruby_method) rsa_set_params, 1);

	rsa_exception = rb_define_class_under(rsa_class, "Error",
			rb_eStandardError);
}

