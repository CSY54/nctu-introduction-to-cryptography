#include <iostream>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"

using byte_string = std::string;
using hex_string = std::string;

byte_string hex_to_byte(hex_string s) {
	byte_string res;

	CryptoPP::StringSource ss(
		s,
		true,
		new CryptoPP::HexDecoder(
			new CryptoPP::StringSink(res)
		)
	);

	return res;
}

hex_string byte_to_hex(byte_string s) {
	hex_string res;

	CryptoPP::StringSource ss(
		s,
		true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(res)
		)
	);

	return res;
}

byte_string int_to_byte(CryptoPP::Integer n) {
	byte_string res;
	res.resize(4);
	n.Encode(reinterpret_cast<CryptoPP::byte*>(res.data()), res.size(), CryptoPP::Integer::UNSIGNED);
	return res;
}

hex_string int_to_hex(CryptoPP::Integer n) {
	return byte_to_hex(int_to_byte(n));
}

/*
 * msg and nonce in byte
 * return byte
 */
byte_string sha256(byte_string msg, byte_string nonce) {
	CryptoPP::SHA256 hash;
	byte_string res;

	CryptoPP::StringSource ss(
		msg + nonce,
		true,
		new CryptoPP::HashFilter(
			hash,
			new CryptoPP::StringSink(res)
		)
	);

#ifdef DEBUG
	std::cout << "sha256(\"" << byte_to_hex(msg) << byte_to_hex(nonce) << "\") = " << byte_to_hex(res) << std::endl;
#endif

	return res;
}

int leading_zero(hex_string s) {
	int i = 0;
	while (i < (int)s.length() && s[i] == '0') {
		i++;
	}
	return i;
}

int main() {
	CryptoPP::Integer nonce("0");
	const CryptoPP::Integer MAX("4294967296");

	char *ID;
	if ((ID = getenv("ID")) == NULL) {
		std::cout << "Please provide ID" << std::endl;
		exit(EXIT_FAILURE);
	}

	byte_string prev_hash = sha256(hex_string(ID), "");
	int max_leading = -1;

	std::ofstream fout("out.txt");

	auto start_time = std::chrono::high_resolution_clock::now();
	while (nonce < MAX) {
#ifdef DEBUG
		if (nonce % 1000000 == 0) {
			std::cout << nonce << std::endl;
		}
#endif

		byte_string hash = sha256(prev_hash, int_to_byte(nonce));
		int leading = leading_zero(byte_to_hex(hash));
		
		if (leading > max_leading) {
			fout << leading << std::endl
				<< byte_to_hex(prev_hash) << std::endl
				<< int_to_hex(nonce) << std::endl
				<< byte_to_hex(hash) << std::endl;

			max_leading = leading;
			prev_hash = hash;
		}

		nonce++;
	}
	auto end_time = std::chrono::high_resolution_clock::now();

	auto ms_int = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

	std::chrono::duration<double, std::milli> ms_double = end_time - start_time;

	std::cout << ms_int.count() << std::endl;
	std::cout << ms_double.count() << std::endl;

	return 0;
}
