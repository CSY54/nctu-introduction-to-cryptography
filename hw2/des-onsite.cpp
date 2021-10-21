#include <iostream>
#include <fstream>
#include <stdint.h>
#include <string>
#include <cassert>


#ifdef DEBUG
#define TO_BIN(x, n) do { \
	std::string c(n, '0'); \
	for (int _i = 0; _i < n; _i++) { \
		c[_i] += (x >> (n - _i)) & 1; \
	} \
	std::cout << __FUNCTION__ << " " << __LINE__ << " " << #x << " " << c << std::endl; \
} while (0)
#else
#define TO_BIN(x, n) {}
#endif


const std::string KEY = "37198391";
const std::string CIPHERTEXT = "361FD00BAC1D5809";
const std::string PLAINTEXT = "security";


class DES {
private:
	uint64_t sub_keys[16];

	const uint8_t IP[64] = {
		58, 50, 42, 34, 26, 18, 10,  2,
		60, 52, 44, 36, 28, 20, 12,  4,
		62, 54, 46, 38, 30, 22, 14,  6,
		64, 56, 48, 40, 32, 24, 16,  8,
		57, 49, 41, 33, 25, 17,  9,  1,
		59, 51, 43, 35, 27, 19, 11,  3,
		61, 53, 45, 37, 29, 21, 13,  5,
		63, 55, 47, 39, 31, 23, 15,  7,
	};

	const uint8_t FP[64] = {
		40,  8, 48, 16, 56, 24, 64, 32,
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
	};

	const uint8_t E[48] = {
		32,  1,  2,  3,  4,  5,
		 4,  5,  6,  7,  8,  9,
		 8,  9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32,  1,
	};

	const uint8_t S[8][64] = {
		{
			14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
			 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
			 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
			15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
		},
		{
			15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
			 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
			 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
			13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
		},
		{ // swapped
			 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
			13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
		},
		{ // swapped
			10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
			13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
		},
		{
			 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
			14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
		},
		{
			12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
			10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
		},
		{
			 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
			13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
		},
		{
			13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
			 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
		},
	};

	const uint8_t P[48] = {
		16,  7, 20, 21, 29, 12, 28, 17,
		 1, 15, 23, 26,  5, 18, 31, 10,
		 2,  8, 24, 14, 32, 27,  3,  9,
		19, 13, 30,  6, 22, 11,  4, 25,
	};

	const uint8_t PC1[56] = {
		57, 49, 41, 33, 25, 17,  9,
		 1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		 7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4,
	};

	const uint8_t PC2[56] = {
		14, 17, 11, 24,  1,  5,
		 3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32,
	};

	const uint8_t KEY_SHIFTS[16] = { // changed
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
	};

	uint32_t rol(uint32_t x, uint8_t shift, uint8_t bits) {
		return ((x << shift) | (x >> (bits - shift))) & ((1 << bits) -  1);
	}

	uint64_t initial_permutation(uint64_t s) {
		uint64_t res = 0;
		for (uint8_t i = 0; i < 64; i++) {
			res <<= 1;
			res |= (s >> (64 - IP[i])) & 1;
		}

		return res;
	}

	uint64_t final_permutation(uint64_t s) {
		uint64_t res = 0;
		for (uint8_t i = 0; i < 64; i++) {
			res <<= 1;
			res |= (s >> (64 - FP[i])) & 1;
		}

		return res;
	}

	uint64_t expansion(uint32_t s) {
		uint64_t res = 0;

		TO_BIN(s, 32);

		res |= ((s << 5) | (s >> (32 - 5))) & 0x3F;
		TO_BIN(res, 48);
		res <<= 6;
		res |= (s >> (32 - 9)) & 0x3F;
		TO_BIN(res, 48);
		res <<= 6;
		res |= (s >> (32 - 13)) & 0x3F;
		TO_BIN(res, 48);
		res <<= 6;
		res |= (s >> (32 - 17)) & 0x3F;
		TO_BIN(res, 48);
		res <<= 6;
		res |= (s >> (32 - 21)) & 0x3F;
		TO_BIN(res, 48);
		res <<= 6;
		res |= (s >> (32 - 25)) & 0x3F;
		TO_BIN(res, 48);
		res <<= 6;
		res |= (s >> (32 - 29)) & 0x3F;
		TO_BIN(res, 48);
		res <<= 6;
		res |= ((s << 1) | (s >> (32 - 1))) & 0x3F;
		TO_BIN(res, 48);

		return res;
	}

	uint32_t f(uint32_t R, uint64_t K) {
		uint64_t expanded_R = expansion(R);

		assert(expanded_R >> 48 == 0);
		assert(K >> 48 == 0);

		uint64_t t = expanded_R ^ K;

		uint32_t trans = 0;
		for (uint8_t i = 0; i < 8; i++) {
			uint8_t bits  = (t >> (6 * (8 - i - 1))) & 0x3F;
			uint8_t row = ((bits >> 5) << 1) | (bits & 1);
			uint8_t col = (bits >> 1) & 0xF;

			assert(row >> 2 == 0);
			assert(col >> 4 == 0);

			trans <<= 4;
			trans |= S[i][(row << 4) | col];
		}

		uint32_t res = 0;
		for (uint8_t i = 0; i < 32; i++) {
			res <<= 1;
			res |= (trans >> (32 - P[i])) & 1;
		}

		return res;
	}

	void gen_key(uint64_t key, uint64_t *sk) {
		uint64_t permuted = 0;
		for (uint8_t i = 0; i < 56; i++) {
			permuted <<= 1;
			permuted |= (key >> (64 - PC1[i])) & 1;
		}

		uint32_t C = (permuted >> 28) & 0xFFFFFFF;
		uint32_t D = permuted & 0xFFFFFFF;
		for (uint8_t i = 0; i < 16; i++) {
			C = rol(C, KEY_SHIFTS[i], 28);
			D = rol(D, KEY_SHIFTS[i], 28);

			uint64_t k = ((uint64_t)C << 28) | (uint64_t)D;
			uint64_t res = 0;
			for (uint8_t j = 0; j < 48; j++) {
				res <<= 1;
				res |= (k >> (56 - PC2[j])) & 1;
			}

			sk[i] = res;
			TO_BIN(res, 48);
			TO_BIN(sk[i], 48);
		}
	}

public:
	DES(uint64_t key) {
		gen_key(key, sub_keys);
	}

	uint64_t encrypt(uint64_t plaintext) {
		plaintext = initial_permutation(plaintext);

		uint32_t l = plaintext >> 32;
		uint32_t r = plaintext & 0xFFFFFFFF;
		uint32_t l2;
		uint32_t r2;
		for (uint8_t i = 0; i < 16; i++) {
			l2 = r;
			r2 = l ^ f(r, sub_keys[i]);

			l = l2;
			r = r2;
		}

		uint64_t ciphertext = final_permutation(((uint64_t)r << 32) | (uint64_t)l);

		return ciphertext;
	}

	uint64_t decrypt(uint64_t ciphertext) {
		ciphertext = initial_permutation(ciphertext);

		uint32_t l = ciphertext >> 32;
		uint32_t r = ciphertext & 0xFFFFFFFF;
		uint32_t l2;
		uint32_t r2;
		for (uint8_t i = 0; i < 16; i++) {
			l2 = r;
			r2 = l ^ f(r, sub_keys[16 - i - 1]);

			l = l2;
			r = r2;
		}

		uint64_t plaintext = final_permutation(((uint64_t)r << 32) | (uint64_t)l);

		return plaintext;
	}

	/* Helpers */

	static uint64_t string_to_int(std::string s) {
		assert(s.length() <= 8);

		uint64_t res = 0;
		for (uint8_t i = 0; i < 8; i++) {
			res = (res << 8) | s[i];
		}

		return res;
	}

	static std::string int_to_string(uint64_t s) {
		std::string res(8, '\x00');

		for (uint8_t i = 0; i < 8; i++) {
			res[i] = (s >> (8 * (8 - i - 1))) & 0x7F;
		}

		return res;
	}

	static std::string int_to_hex(uint64_t decimal) {
		std::string res(16, '0');

		static const uint8_t HEX[16] = {
			'0', '1', '2', '3', '4', '5', '6', '7',
			'8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
		};

		for (uint8_t i = 0; i < 16; i++) {
			res[i] = HEX[(decimal >> (4 * (16 - i - 1))) & 0xF];
		}

		return res;
	}

	static uint64_t hex_to_int(std::string s) {
		return std::strtoull(s.c_str(), nullptr, 16);
	}
};


int main() {
	DES demo_enc(DES::string_to_int("37198391"));
	uint64_t ciphertext = demo_enc.encrypt(DES::string_to_int("security"));
	std::cout << DES::int_to_hex(ciphertext) << std::endl;


	DES demo_dec(DES::string_to_int("37198391"));
	uint64_t plaintext = demo_dec.decrypt(DES::hex_to_int("361FD00BAC1D5809"));
	std::cout << DES::int_to_string(plaintext) << std::endl;

	return 0;
}
