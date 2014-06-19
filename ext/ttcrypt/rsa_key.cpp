//
//  RsaKey.cpp
//  zcoin
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

#include "rsa_key.h"
#include "ttcrypt.h"
#include <assert.h>
#include <future>

using namespace ttcrypt;
using namespace thrift;

namespace ttcrypt {

static byte_buffer mgf1(const byte_buffer& z, size_t l) {
	const size_t hLen = 20;
	byte_buffer t;
	for (unsigned i = 0; i <= l / hLen; i++)
		t += sha1(z + i2osp(i, 4));
	return byte_buffer(t, 0, l - 1);
}

byte_buffer eme_oaep_encode(const byte_buffer& message, size_t emLen,
		const byte_buffer& p, const byte_buffer* pseed) {
	const size_t hLen = 20;
	const size_t hLen2 = 2 * hLen;

	size_t mLen = message.size();

	if (emLen <= hLen2 + 1)
		throw rsa_key::error("padded length too small");
	if (mLen >= emLen - 1 - hLen2 || mLen > emLen - 2 * hLen2 - 1)
		throw rsa_key::error("message too long");

	byte_buffer ps = byte_buffer('\0', emLen - mLen - hLen2 - 1);
	byte_buffer pHash = sha1(p);
	byte_buffer db = pHash + ps + "\001" + message;
	byte_buffer seed = (pseed != 0) ? *pseed : byte_buffer::random(hLen);
	byte_buffer dbMask = mgf1(seed, emLen - hLen);
	byte_buffer maskedDb = db ^ dbMask;
	byte_buffer seedMask = mgf1(maskedDb, hLen);
	byte_buffer maskedSeed = seed ^ seedMask;

	return maskedSeed + maskedDb;
}

byte_buffer eme_oaep_decode(const byte_buffer& message, const byte_buffer& p) {
	const size_t hLen = 20;
	if (message.size() < hLen * 2 + 1)
		throw rsa_key::error("message is too short");

	byte_buffer maskedSeed(message, 0, hLen - 1);
	byte_buffer maskedDb(message, hLen, -1);
	auto seedMask = mgf1(maskedDb, hLen);
	auto seed = maskedSeed ^ seedMask;
	auto db_mask = mgf1(seed, message.size() - hLen);
	auto db = maskedDb ^ db_mask;
	auto pHash = sha1(p);

	int index = db.index_of('\001', hLen);
	if (index < 0)
		throw rsa_key::error("message is invalid");

	byte_buffer pHash2(db, 0, hLen - 1);
	byte_buffer ps(db, hLen, index - 1);
	byte_buffer m(db, index + 1, -1);

	for (auto x : ps) {
		if (x != '\0')
			throw rsa_key::error("message is invalid");
	}

	if (pHash2 != pHash)
		throw rsa_key::error("wrong p value");

	return m;
}

byte_buffer rsa_key::rsadp(const byte_buffer& ciphertext) const {
	big_integer c = big_integer(ciphertext);
	if (c >= n - 1)
		throw rsa_key::error("cipertext is too long");
	if (fast_key) {
		// Fast
		auto m1 = powmod_sec((c % p), dp, p);
		auto m2 = powmod_sec((c % q), dq, q);
		auto h = ((m1 - m2) * q_inv) % p;
		return i2osp(m2 + q * h, byte_size - 1);
	} else {
		// slow c^d mod n
		if (d == 0)
			throw rsa_key::error("missing private key");
		return i2osp(powmod_sec(c, d, n), byte_size - 1);
	}
}

byte_buffer emsa_pss_encode(const byte_buffer& message, size_t emBits,
		byte_buffer (*hash)(const byte_buffer&), const byte_buffer *_salt = 0) {
	auto mHash = hash(message);
	auto hLen = mHash.size();

	// TODO: implement bits logic!
	auto emLen = (emBits + 7) / 8;

	// required: emLen < hLen + sLen + 2
	size_t sLen;
	byte_buffer salt;
	if (_salt) {
		salt = *_salt;
		sLen = salt.size();
	} else {
		sLen = emLen - hLen - 2;
		salt = byte_buffer::random(sLen);
	}

	if (emLen < hLen + sLen + 2)
		throw rsa_key::error("invliad salt length");

	auto M1 = byte_buffer('\0', 8) + mHash + salt;
	auto H = hash(M1);
	auto PS = byte_buffer('\0', emLen - sLen - hLen - 2);
	auto DB = PS.append_byte(1) + salt;
	auto dbMask = mgf1(H, emLen - hLen - 1);

	auto maskedDb = DB ^ dbMask;

	// Clear leftmost bits
	auto clear_bits = 8 * emLen - emBits;
	if (clear_bits > 0)
		maskedDb.set(0, clear_left_bits(maskedDb.at(0), clear_bits));

	return maskedDb + H + "\xbc";
}

bool emsa_pss_verify(const byte_buffer& source_message,
		const byte_buffer& encoded_message, size_t emBits,
		byte_buffer (*hash)(const byte_buffer&), size_t sLen) {

	auto mHash = hash(source_message);
	auto emLen = (emBits + 7) / 8;

	size_t hLen = mHash.size();
	if (sLen == 0)
		sLen = emLen - hLen - 2;

	if (emLen < hLen + sLen + 2 || encoded_message[-1] != 0xbc)
		return false;

	byte_buffer maskedDB(encoded_message, 0, emLen - hLen - 2); // range is inclusive!

	// Check MSB bits are cleared
	auto clear_bits = 8 * emLen - emBits;
	if (clear_bits > 0) {
		byte bitmask = 0x80;
		for (unsigned bit_no = 0; bit_no++ < clear_bits;) {
			if ((maskedDB[0] & bitmask) != 0) // Compiler should optimize this
				return false;
		}
	}

	byte_buffer H(encoded_message, emLen - hLen - 1, emLen - 2); // range inclusive
	auto dbMask = mgf1(H, emLen - hLen - 1);

	auto DB = maskedDB ^ dbMask;

	DB.set(0, clear_left_bits(DB[0], clear_bits));

	for (unsigned i = 0; i < emLen - hLen - sLen - 2; i++) {
		if (DB[i] != 0) {
			return false;
		}
	}

	if (DB[emLen - hLen - sLen - 2] != 1)
		return false;

	byte_buffer salt(DB, -sLen, -1);

	auto M1 = byte_buffer('\0', 8) + mHash + salt;
	auto H1 = hash(M1);
	return H == H1;
}

// Note that signing does not require blinding - it is not prone to the
// timing attack
byte_buffer rsa_key::rsasp1(const byte_buffer &message) const {
	big_integer m = message;
	if (m >= n)
		throw rsa_key::error("message representative is too long");
	if (fast_key) {
		// Fast
		auto s1 = powmod(m % p, dp, p);
		auto s2 = powmod(m % q, dq, q);
		auto h = (s1 - s2) * q_inv % p;
		auto s = s2 + q * h;
		return i2osp(s, byte_size);
	} else {
		// slow
		if (d == 0)
			throw rsa_key::error("missing private key");
		return i2osp(powmod(m, d, n), byte_size);
	}
}

byte_buffer rsa_key::rsavp1(const byte_buffer& signature) const {
	big_integer s = signature;
	if (s > n - 1)
		throw invalid_argument("signature representative too big");
	require_public_key();
	return i2osp(powmod_sec(s, e, n), byte_size);
}

bool rsa_key::verify(const byte_buffer& message, const byte_buffer& signature,
		byte_buffer (*hash)(const byte_buffer&), size_t s_len) const {
	if (signature.size() != byte_size)
		return false;
	try {
		return emsa_pss_verify(message, rsavp1(signature), bits_size - 1, hash,
				s_len);
	} catch (const invalid_argument& e) {
		return false;
	}
}

void rsa_key::normalize_key() {
	if (n == 0)
		n = p * q;
	if ((dp == 0 || dq == 0 || q_inv == 0) && p != 0 && q != 0) {
		dp = inverse(e, p - 1);
		dq = inverse(e, q - 1);
		q_inv = inverse(q, p);
		fast_key = true;
	} else
		fast_key = p != 0 && q != 0 && dp != 0 && dq != 0 && q_inv != 0;
	bits_size = n.bit_length();
	byte_size = (bits_size + 7) / 8;
}

static big_integer prime(unsigned bits) {
	// Set 2 MSB bits to ensire we git enough big pq
	// and calculate margin
	big_integer r = (1_b << (bits - 2)) + (1_b << (bits - 1));
	big_integer s = (1_b << bits) - 1;
	while (1) {
		auto p = next_prime(big_integer::random_between(r, s));
		if (p <= s)
			return p;
		// loop if prime is too big (unlikely)
	}
	throw logic_error("failed prime generation");
}

rsa_key rsa_key::generate(unsigned int k, size_t e) {
	if (e == 0)
		e = 0x10001;

	if (e < 3 || (e != 0x10001 && !big_integer(e).is_prime()))
		throw rsa_key::error("exponent should be prime number >= 3");

	// v2.2 Algorithm
	while (true) {
		auto future = std::async(std::launch::async, [k] {return prime(k/2);});
		auto q = prime(k - k / 2);
		auto p = future.get();
		if (p == q)
			continue;

		auto n = p * q;
		if (n.bit_length() != k) {
			// logic error: bit length mismatch, regenerating
			continue;
		}

		auto Ln = lcm(p - 1, q - 1);
		if (gcd(e, Ln) != 1)
			continue;

		if (p > q)
			swap(p, q);

		return rsa_key(n, e, p, q);
	}
	throw logic_error("pq generation failed");
}

void rsa_key::set(string name, const thrift::big_integer &value) {
	std::transform(name.begin(), name.end(), name.begin(), ::tolower);
	switch (name[0]) {
	case 'e':
		e = value;
		break;
	case 'p':
		this->p = value;
		break;
	case 'q':
		if (name == "qinv" || name == "q_inv")
			q_inv = value;
		else
			q = value;
		break;
	case 'n':
		n = value;
		break;
	case 'd':
		if (name == "dp") {
			dp = value;
		} else if (name == "dq") {
			dq = value;
		} else
			d = value;
		break;
	default:
		throw error("unknown paramerer ");
		break;
	}
}

unordered_map<string, big_integer> rsa_key::get_params(bool include_all) const
		noexcept {
	unordered_map<string, big_integer> params;
	if (n != 0) {
		params["n"] = n;
	}
	if (e != 0) {
		params["e"] = e;
	}
	if (p != 0) {
		params["p"] = p;
	}
	if (q != 0) {
		params["q"] = q;
	}

	if (d != 0 && ((p == 0 && q == 0) || include_all)) {
		params["d"] = q;
	}

	if (dp != 0 && include_all) {
		params["dp"] = dp;
	}

	if (dq != 0 && include_all) {
		params["dq"] = dq;
	}

	if (q_inv != 0 && include_all) {
		params["qinv"] = q_inv;
	}

	return params;
}

}

