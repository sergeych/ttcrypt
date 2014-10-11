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

#include <future>
#include "rsa_key.h"
#include "ttcrypt.h"

using namespace ttcrypt;
using namespace thrift;

namespace ttcrypt {

static byte_buffer mgf1(const byte_buffer& z, size_t l) {
	const size_t hLen = 20;
	byte_buffer t;
	for (unsigned i = 0; i <= l / hLen; i++) {
		t += sha1(z + i2osp(i, 4));
	}
	return byte_buffer(t, 0, l - 1);
}

byte_buffer eme_oaep_encode(const byte_buffer& message, size_t emLen,
		const byte_buffer* p, const byte_buffer* pseed) {
	const size_t hLen = 20;
	const size_t hLen2 = 2 * hLen;

	size_t mLen = message.size();

	if (emLen <= hLen2 + 1)
		throw rsa_key::error("padded length too small");
	if (mLen >= emLen - 1 - hLen2 || mLen > emLen - 2 * hLen2 - 1)
		throw rsa_key::error("message too long");

	auto ps = byte_buffer::pad('\0', emLen - mLen - hLen2 - 1);
	auto pHash = sha1(p ? *p : "");
	auto db = pHash + ps + "\001" + message;
	auto seed = (pseed != 0) ? *pseed : byte_buffer::random(hLen);
	auto dbMask = mgf1(seed, emLen - hLen);
	auto maskedDb = db ^ dbMask;
	auto seedMask = mgf1(maskedDb, hLen);
	auto maskedSeed = seed ^ seedMask;

	return maskedSeed + maskedDb;
}

byte_buffer eme_oaep_decode(const byte_buffer& message, const byte_buffer* p) {
	const size_t hLen = 20;
	if (message.size() < hLen * 2 + 1)
		throw rsa_key::error("message is too short");

	byte_buffer maskedSeed(message, 0, hLen - 1);
	byte_buffer maskedDb(message, hLen, -1);
	auto seedMask = mgf1(maskedDb, hLen);
	auto seed = maskedSeed ^ seedMask;
	auto db_mask = mgf1(seed, message.size() - hLen);
	auto db = maskedDb ^ db_mask;
	auto pHash = sha1(p ? *p : "");

	int index = db.index_of('\001', hLen);
	if (index < 0)
		throw rsa_key::error("message is invalid (no 1)");

	byte_buffer pHash2(db, 0, hLen - 1);
	byte_buffer ps(db, hLen, index - 1);
	byte_buffer m(db, index + 1, -1);

	for (auto x : ps) {
		if (x != '\0')
			throw rsa_key::error("message is invalid (zero padding)");
	}

	if (pHash2 != pHash)
		throw rsa_key::error("wrong p value");

	return m;
}

byte_buffer rsa_key::rsadp(const byte_buffer& ciphertext) const {
	big_integer c = ciphertext;
	if (c >= n - 1)
		throw rsa_key::error("ciphertext is too long");
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

	auto M1 = byte_buffer::pad('\0', 8) + mHash + salt;
	auto H = hash(M1);
	auto PS = byte_buffer::pad('\0', emLen - sLen - hLen - 2);
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

	auto M1 = byte_buffer::pad('\0', 8) + mHash + salt;
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
#ifdef NO_FUTURE
		auto q = prime(k - k / 2);
		auto p = prime(k/2);
#else
		auto future = std::async(std::launch::async, [k] {return prime(k/2);});
		auto q = prime(k - k / 2);
		auto p = future.get();
#endif
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

void rsa_key::set(const string& name, const thrift::big_integer &value) {
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

static ostream *pout;

#define LHEX(text,data) {*pout<<text<<":\n"<<data.hex(16)<<endl;}

#define REQUIRE(x) if(!(x)){*pout<<"Failed "<<(#x)<<" @"<<__FILE__<<":"<<__LINE__<<endl; return false;}


bool rsa_key::self_test(ostream& out) {
	pout = &out;
	{
        	out << "we start..." << endl;
        	big_integer mi = pow(2_b,1024) - 173_b;

        	if( big_integer(mi.to_byte_buffer()) != mi ) {
        		out << "Decoding problem" << endl;
        		return false;
        	}
        	byte_buffer res = i2osp(65537_b);
        	if( res.hex() != "01 00 01") {
        		out << "i2osp fail: " << res.hex() << endl;
        		return false;
        	}

        	mi = os2ip(res);
        	if( mi != 65537_b ) {
        		out << "I2OSP/OS2IP failure: Result is not 65537: " << mi << endl;
        		return false;
        	}

        	mi = pow(2_b,1023) - 1_b;
        	byte_buffer x = rsadp( rsaep(mi.to_byte_buffer()) );

        	if( big_integer(x) != mi ) {
        		out << "Big integer failure: " << big_integer(x) << endl;
        		return false;
        	}


        	byte_buffer src("hello!");
        	if( i2osp( os2ip(src), 6) != src ) {
        		out << "Failed osp2: " << i2osp( os2ip(src), 6) << endl;
        		return false;
        	}

        	string sres = i2osp(254,3).hex();
        	if( sres != "00 00 fe" ) {
        		out << "i20sp padding failure: " << sres << endl;
        		return false;
        	}

        	if( sha1("abc") != decode_hex("a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d") ) {
        		out << "SHA1 failed: " << sha1("abc").hex() << endl;
        		return false;
        	}

        	if( sha1("") != decode_hex("da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709") ) {
        		out << "SHA1 of empty string failed: " << sha1("").hex() << endl;
        		return false;
        	}

        	res = eme_oaep_decode(eme_oaep_encode(src, 127, 0, 0), 0);
        	if( res != src ) {
        		out << "OAEP failed: " << res;
        		return false;
        	}

	}
	{
		out << "RSAES test" << endl;
	    auto message = decode_hex("d4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49");

	    auto seed = decode_hex("aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f");

	    auto encoded_message = decode_hex("\
	                                      eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26 dc d8 7d 5c 68\
	                                      f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46 26 f5 af f9 3e dc\
	                                      fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe 4f f4 77 28 b4 a1 b7 c1 36\
	                                      2b aa d2 9a b4 8d 28 69 d5 02 41 21 43 58 11 59 1b e3 92 f9 82 fb 3e 87 d0\
	                                      95 ae b4 04 48 db 97 2f 3a c1 4f 7b c2 75 19 52 81 ce 32 d2 f1 b7 6d 4d 35\
	                                      3e 2d");

	    auto encrypted_message = decode_hex("\
	                                        12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0 39 a3 3d 1e 99 6f c8 2a 94\
	                                        cc d3 00 74 c9 5d f7 63 72 20 17 06 9e 52 68 da 5d 1c 0b 4f 87 2c f6 53 c1\
	                                        1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb 6d 84 b1 c3 1d 65 4a 19 70 e5 78\
	                                        3b d6 eb 96 a0 24 c2 ca 2f 4a 90 fe 9f 2e f5 c9 c1 40 e5 bb 48 da 95 36 ad\
	                                        87 00 c8 4f c9 13 0a de a7 4e 55 8d 51 a7 4d df 85 d8 b5 0d e9 68 38 d6 06\
	                                        3e 09 55");

        auto n = decode_hex("\
                            bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71 f7 36 8d 07 ee d4 10 43 a4\
                            40 d6 b6 f0 74 54 f5 1f b8 df ba af 03 5c 02 ab 61 ea 48 ce eb 6f cd 48\
                            76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80 7f af b8 e0 a3 df c7 37 72\
                            3e e6 b4 b7 d9 3a 25 84 ee 6a 64 9d 06 09 53 74 88 34 b2 45 45 98 39 4e\
                            e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1 68 7f e2 53 72 98 ca 2a 8f 59\
                            46 f8 e5 fd 09 1d bd cb");

        unsigned e = 0x11;

        auto p = decode_hex("\
                            ee cf ae 81 b1 b9 b3 c9 08 81 0b 10 a1 b5 60 01 99 eb 9f 44 ae f4 fd a4\
                            93 b8 1a 9e 3d 84 f6 32 12 4e f0 23 6e 5d 1e 3b 7e 28 fa e7 aa 04 0a 2d\
                            5b 25 21 76 45 9d 1f 39 75 41 ba 2a 58 fb 65 99");

        auto q = decode_hex("\
                            c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35 3f 6c 42 d0 88 66 b1 d0\
                            5a 0f 20 35 02 8b 9d 86 98 40 b4 16 66 b4 2e 92 ea 0d a3 b4 32 04 b5 cf\
                            ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03");

//        auto dP = decode_hex("\
//                             54 49 4c a6 3e ba 03 37 e4 e2 40 23 fc d6 9a 5a eb 07 dd dc 01 83 a4 d0\
//                             ac 9b 54 b0 51 f2 b1 3e d9 49 09 75 ea b7 74 14 ff 59 c1 f7 69 2e 9a 2e\
//                             20 2b 38 fc 91 0a 47 41 74 ad c9 3c 1f 67 c9 81");
//
//        auto dQ = decode_hex("\
//                             47 1e 02 90 ff 0a f0 75 03 51 b7 f8 78 86 4c a9 61 ad bd 3a 8a 7e 99 1c\
//                             5c 05 56 a9 4c 31 46 a7 f9 80 3f 8f 6f 8a e3 42 e9 31 fd 8a e4 7a 22 0d\
//                             1b 99 a4 95 84 98 07 fe 39 f9 24 5a 98 36 da 3d");
//
//        auto qInv = decode_hex("\
//                               b0 6c 4f da bb 63 01 19 8d 26 5b db ae 94 23 b3 80 f2 71 f7 34 53 88 50\
//                               93 07 7f cd 39 e2 11 9f c9 86 32 15 4f 58 83 b1 67 a9 67 bf 40 2b 4e 9e\
//                               2e 0f 96 56 e6 98 ea 36 66 ed fb 25 79 80 39 f7");

        rsa_key key(n, e, p, q);
        key.debug_seed(seed);

        REQUIRE( key.encrypt(message).hex() == encrypted_message.hex() );
        REQUIRE( key.decrypt(encrypted_message).hex() == message.hex() );

        rsa_key key2(n, e, p, q);
        REQUIRE( key2.is_private() == true);

        REQUIRE( key2.decrypt(encrypted_message).hex() == message.hex() );
	}
	{
	out << "Sign test" << endl;

    auto signing_salt = decode_hex("e3 b5 d5 d0 02 c1 bc e5 0c 2b 65 ef 88 a1 88 d8 3b ce 7e 61");

    auto message = decode_hex("85 9e ef 2f d7 8a ca 00 30 8b dc 47 11 93 bf 55"
                              "bf 9d 78 db 8f 8a 67 2b 48 46 34 f3 c9 c2 6e 64"
                              "78 ae 10 26 0f e0 dd 8c 08 2e 53 a5 29 3a f2 17"
                              "3c d5 0c 6d 5d 35 4f eb f7 8b 26 02 1c 25 c0 27"
                              "12 e7 8c d4 69 4c 9f 46 97 77 e4 51 e7 f8 e9 e0"
                              "4c d3 73 9c 6b bf ed ae 48 7f b5 56 44 e9 ca 74"
                              "ff 77 a5 3c b7 29 80 2f 6e d4 a5 ff a8 ba 15 98"
                              "90 fc");
    auto EM = decode_hex(
                         "66 e4 67 2e 83 6a d1 21 ba 24 4b ed 65 76 b8 67"
                         "d9 a4 47 c2 8a 6e 66 a5 b8 7d ee 7f bc 7e 65 af"
                         "50 57 f8 6f ae 89 84 d9 ba 7f 96 9a d6 fe 02 a4"
                         "d7 5f 74 45 fe fd d8 5b 6d 3a 47 7c 28 d2 4b a1"
                         "e3 75 6f 79 2d d1 dc e8 ca 94 44 0e cb 52 79 ec"
                         "d3 18 3a 31 1f c8 96 da 1c b3 93 11 af 37 ea 4a"
                         "75 e2 4b db fd 5c 1d a0 de 7c ec df 1a 89 6f 9d"
                         "8b c8 16 d9 7c d7 a2 c4 3b ad 54 6f be 8c fe bc");

    //# RSA modulus n:
    auto n = decode_hex("\
                        a2 ba 40 ee 07 e3 b2 bd 2f 02 ce 22 7f 36 a1 95\
                        02 44 86 e4 9c 19 cb 41 bb bd fb ba 98 b2 2b 0e\
                        57 7c 2e ea ff a2 0d 88 3a 76 e6 5e 39 4c 69 d4\
                        b3 c0 5a 1e 8f ad da 27 ed b2 a4 2b c0 00 fe 88\
                        8b 9b 32 c2 2d 15 ad d0 cd 76 b3 e7 93 6e 19 95\
                        5b 22 0d d1 7d 4e a9 04 b1 ec 10 2b 2e 4d e7 75\
                        12 22 aa 99 15 10 24 c7 cb 41 cc 5e a2 1d 00 ee\
                        b4 1f 7c 80 08 34 d2 c6 e0 6b ce 3b ce 7e a9 a5");

    //# RSA public exponent e:
    auto e =        0x010001;
    //
    //# Prime p:
    auto p = decode_hex("\
                        d1 7f 65 5b f2 7c 8b 16 d3 54 62 c9 05 cc 04 a2\
                        6f 37 e2 a6 7f a9 c0 ce 0d ce d4 72 39 4a 0d f7\
                        43 fe 7f 92 9e 37 8e fd b3 68 ed df f4 53 cf 00\
                        7a f6 d9 48 e0 ad e7 57 37 1f 8a 71 1e 27 8f 6b");

    //# Prime q:
    auto q = decode_hex("\
                        c6 d9 2b 6f ee 74 14 d1 35 8c e1 54 6f b6 29 87\
                        53 0b 90 bd 15 e0 f1 49 63 a5 e2 63 5a db 69 34\
                        7e c0 c0 1b 2a b1 76 3f d8 ac 1a 59 2f b2 27 57\
                        46 3a 98 24 25 bb 97 a3 a4 37 c5 bf 86 d0 3f 2f");

    auto signature = decode_hex("\
                                8d aa 62 7d 3d e7 59 5d 63 05 6c 7e c6 59 e5 44\
                                06 f1 06 10 12 8b aa e8 21 c8 b2 a0 f3 93 6d 54\
                                dc 3b dc e4 66 89 f6 b7 95 1b b1 8e 84 05 42 76\
                                97 18 d5 71 5d 21 0d 85 ef bb 59 61 92 03 2c 42\
                                be 4c 29 97 2c 85 62 75 eb 6d 5a 45 f0 5f 51 87\
                                6f c6 74 3d ed dd 28 ca ec 9b b3 0e a9 9e 02 c3\
                                48 82 69 60 4f e4 97 f7 4c cd 7c 7f ca 16 71 89\
                                71 23 cb d3 0d ef 5d 54 a2 b5 53 6a d9 0a 74 7e");

    auto padded = emsa_pss_encode(message, 1023, sha1, &signing_salt);
    REQUIRE( padded.hex() == EM.hex() );
    REQUIRE(true == emsa_pss_verify(message, padded, 1023, sha1, signing_salt.size()));
    REQUIRE(false == emsa_pss_verify(message+"!", padded, 1023, sha1, signing_salt.size()));
    padded.set(0, padded[0] ^ 3);
    REQUIRE(false == emsa_pss_verify(message, padded, 1023, sha1, signing_salt.size()));

    rsa_key key(n, e, p, q);
    auto s = key.sign(message, sha1, &signing_salt);
    REQUIRE( s == signature );
    REQUIRE( key.verify(message, s, sha1, signing_salt.size()) == true );

    s = key.sign(message+"!", sha1, &signing_salt);
    REQUIRE( s != signature );
	}
	return true;
}

}

