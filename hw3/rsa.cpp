#include <iostream>
#include <fstream>
#include <cassert>

#include "cryptopp/rsa.h"
#include "cryptopp/misc.h"
#include "cryptopp/osrng.h"

struct Part_1 {
	int key_length;
	CryptoPP::Integer n;
	CryptoPP::Integer e;
	std::string plaintext;

	Part_1(
		int _key_length,
		const char *_n,
		const char *_e,
		std::string _plaintext
	) :
		key_length(_key_length),
		n(CryptoPP::Integer(_n)),
		e(CryptoPP::Integer(_e)),
		plaintext(_plaintext) {}
};

struct Part_2 {
	int key_length;
	CryptoPP::Integer n;
	CryptoPP::Integer e;
	CryptoPP::Integer partial_d;
	CryptoPP::Integer ciphertext;

	Part_2(
		int _key_length,
		const char *_n,
		const char *_e,
		const char *_partial_d,
		const char *_ciphertext
	) :
		key_length(_key_length),
		n(CryptoPP::Integer(_n)),
		e(CryptoPP::Integer(_e)),
		partial_d(CryptoPP::Integer(_partial_d)),
		ciphertext(CryptoPP::Integer(_ciphertext)) {}
};

#ifdef DEBUG
const Part_1 DEBUG_RSA_1 = {
	64,
	"0xc963f963d93559ff",
	"0x11",
	"ElGamal",
};

const std::string DEBUG_RSA_CIPHERTEXT = "6672e7d4a8786631";
#endif

const Part_1 CASE_1_1 = {
	128,
	"0x04823f9fe38141d93f1244be161b20f",
	"0x11",
	"Hello World!",
};

const Part_1 CASE_1_2 = {
	256,
	"0x9711ea5183d50d6a91114f1d7574cd52621b35499b4d3563ec95406a994099c9",
	"0x10001",
	"RSA is public key.",
};

#ifdef DEBUG
const Part_2 DEBUG_RSA_2_1 = {
	64,
	"0xc45350fa19fa8d93",
	"0x11",
	"0x454a950c5bcbaa41",
	"0xa4a59490b843eea0",
};

const Part_2 DEBUG_RSA_2_2 = {
	64,
	"0xc45350fa19fa8d93",
	"0x11",
	"0x454a950c5bc00000",
	"0xa4a59490b843eea0",
};

const std::string DEBUG_RSA_PLAINTEXT = "secrecy";
#endif

const Part_2 CASE_2_1 = {
	128,
	"0xc4b361851de35f080d3ca7352cbf372d",
	"0x1d35",
	"0x53a0a95b089cf23adb5cc73f0700000",
	"0xa02d51d0e87efe1defc19f3ee899c31d",
};

std::string integer_to_string(CryptoPP::Integer x) {
	std::string res(x.MinEncodedSize(), '\x00');

	x.Encode(
		reinterpret_cast<CryptoPP::byte*>(res.data()),
		res.size(),
		CryptoPP::Integer::UNSIGNED
	);

	return res;
}

// Seems that raw RSA has no pipeline
std::string rsa_encrypt(Part_1 rsa_info) {
	CryptoPP::RSA::PublicKey pubkey;
	pubkey.Initialize(rsa_info.n, rsa_info.e);

	CryptoPP::Integer plaintext(
		reinterpret_cast<const CryptoPP::byte*>(rsa_info.plaintext.data()),
		rsa_info.plaintext.size()
	);

	assert(plaintext.BitCount() < rsa_info.n.BitCount());

	CryptoPP::Integer ciphertext = pubkey.ApplyFunction(plaintext);

	return CryptoPP::IntToString(ciphertext, 16);
}

std::pair<std::string, std::string> brute(Part_2 rsa_info) {
	CryptoPP::Integer d = rsa_info.partial_d;
	CryptoPP::AutoSeededRandomPool prng;

	while (true) {
		try {
			CryptoPP::RSA::PrivateKey privkey;
			privkey.Initialize(rsa_info.n, rsa_info.e, d);

			CryptoPP::Integer plaintext = privkey.CalculateInverse(
				prng,
				rsa_info.ciphertext
			);

			assert(plaintext.BitCount() < rsa_info.n.BitCount());

			return {CryptoPP::IntToString(d, 16), integer_to_string(plaintext)};
		} catch (...) {
			d++;
		}
	}
}

int main() {
#ifdef DEBUG
	std::string debug_ciphertext = rsa_encrypt(DEBUG_RSA_1);
	assert(debug_ciphertext == DEBUG_RSA_CIPHERTEXT);
#endif

	std::string case_1_1 = rsa_encrypt(CASE_1_1);
	// std::cout << case_1_1 << std::endl;

	std::string case_1_2 = rsa_encrypt(CASE_1_2);
	// std::cout << case_1_2 << std::endl;

#ifdef DEBUG
	std::pair<std::string, std::string> debug_rsa_2_1 = brute(DEBUG_RSA_2_1);
	assert(debug_rsa_2_1.second == DEBUG_RSA_PLAINTEXT);

	std::pair<std::string, std::string> debug_rsa_2_2 = brute(DEBUG_RSA_2_2);
	assert(debug_rsa_2_2.second == DEBUG_RSA_PLAINTEXT);
#endif

	std::pair<std::string, std::string> case_2_1 = brute(CASE_2_1);
	// std::cout << std::hex << case_2_1.first << std::endl << case_2_1.second << std::endl;

	std::ofstream fout("./out.txt");
	fout << case_1_1 << std::endl
		<< case_1_2 << std::endl
		<< case_2_1.first << std::endl
		<< case_2_1.second << std::endl;

	return 0;
}
