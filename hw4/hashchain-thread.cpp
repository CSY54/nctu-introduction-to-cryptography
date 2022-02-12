/*
 * Not the most recent file
 * Does it still work? dunno
 */
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <mutex>
#include <filesystem>

#include "cryptopp/sha.h"
#include "cryptopp/hex.h"

const int MAX_DIFFICULTY = 30;
const int THREAD_COUNT = 8;
const CryptoPP::Integer MAX_NONCE(4294967296);

using byte_string = std::string;
using hex_string = std::string;

int cnt = 0;
std::mutex cnt_lock;

std::vector<std::ofstream> fout;
// share lock, whatever
std::mutex file_lock;

hex_string byte_to_hex(byte_string s) {
	hex_string res;

	CryptoPP::HexEncoder encoder;
	encoder.Put((const CryptoPP::byte*)s.data(), s.size());
	encoder.MessageEnd();

	res.resize(encoder.MaxRetrievable());
	encoder.Get((CryptoPP::byte*)&res[0], res.size());

	return res;
}

byte_string hex_to_byte(hex_string s) {
	byte_string res;

	CryptoPP::HexDecoder decoder;
	decoder.Put((const CryptoPP::byte*)s.data(), s.size());
	decoder.MessageEnd();

	res.resize(decoder.MaxRetrievable());
	decoder.Get((CryptoPP::byte*)&res[0], res.size());

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
	byte_string digest;

	byte_string data = msg + nonce;
	hash.Update((const CryptoPP::byte*)data.data(), data.size());
	digest.resize(hash.DigestSize());
	hash.Final((CryptoPP::byte*)&digest[0]);

	return digest;
}

int leading_zero(hex_string s) {
	int i = 0;
	while (i < (int)s.length() && s[i] == '0') {
		i++;
	}
	return i;
}

void log(
	int difficulty,
	byte_string prev_hash,
	byte_string nonce,
	byte_string hash
) {
	std::lock_guard<std::mutex> lock(file_lock);

	std::stringstream ss;

	std::cout << "sha256( " << byte_to_hex(prev_hash) << " || " << byte_to_hex(nonce) << " ) = " << byte_to_hex(hash) << std::endl;

	fout[difficulty] << byte_to_hex(prev_hash) << " " << byte_to_hex(nonce) << " " << byte_to_hex(hash) << std::endl;
}

void run(
	int difficulty,
	byte_string prev_hash,
	CryptoPP::Integer from,
	CryptoPP::Integer to
) {
	// std::cout << "difficulty: " << difficulty << " [" << from << ", " << to << "]" << std::endl;
	CryptoPP::Integer nonce(from);
	while (nonce < to) {
		byte_string nonce_byte = int_to_byte(nonce);
		byte_string hash = sha256(prev_hash, nonce_byte);
		int leading = leading_zero(byte_to_hex(hash));

		if (leading == difficulty) {
			log(difficulty, prev_hash, nonce_byte, hash);
			std::lock_guard<std::mutex> lock(cnt_lock);
			cnt++;
		}

		nonce++;
	}
}

int main() {
	const CryptoPP::Integer MAX("4294967296");

	char *ID;
	if ((ID = getenv("ID")) == NULL) {
		std::cout << "Please provide ID" << std::endl;
		exit(EXIT_FAILURE);
	}

	// setup fout
	std::filesystem::create_directory("difficulty");
	fout.resize(MAX_DIFFICULTY + 1);

	for (int i = 1; i <= MAX_DIFFICULTY; i++) {
		std::ofstream f("./difficulty/" + std::to_string(i) + ".txt");
		fout[i] = std::move(f);
	}

	byte_string prev_hash = sha256(hex_string(ID), "");
	int cur_difficulty = 0;

	auto start_time = std::chrono::high_resolution_clock::now();

	CryptoPP::Integer block_size(MAX_NONCE / THREAD_COUNT);
	std::vector<std::thread> threads;
	for (int i = 0; i < THREAD_COUNT; i++) {
		std::thread th(run, cur_difficulty + 1, prev_hash, block_size * i, std::min(block_size * (i + 1), MAX_NONCE));
		threads.emplace_back(move(th));
	}

	for (auto &th : threads) {
		th.join();
	}

	auto end_time = std::chrono::high_resolution_clock::now();

	auto ms_int = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
	std::chrono::duration<double, std::milli> ms_double = end_time - start_time;

	std::cout << "Time used: " << ms_double.count() << std::endl;
	std::cout << "Hash found: " << cnt << std::endl;

	return 0;
}
