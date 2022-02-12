#include <iostream>

#include "cryptopp/modes.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"

std::string CIPHERTEXT = "AC45D78068C2BD87C3F50DEC9F898260";
std::string IV = "0000000000000000";

int main() {
	for (char i = '0'; i <= '9'; i++) {
		for (char j = '0'; j <= '9'; j++) {
			std::string key = std::string(1, i) + std::string(1, j) + "00000000000000";

			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aes;
			std::string plaintext;

			aes.SetKeyWithIV(
				reinterpret_cast<const CryptoPP::byte*>(key.data()),
				key.size(),
				reinterpret_cast<const CryptoPP::byte*>(IV.data())
			);

			try {
				CryptoPP::StringSource ss(
					CIPHERTEXT,
					true,
					new CryptoPP::HexDecoder(
						new CryptoPP::StreamTransformationFilter(
							aes,
							new CryptoPP::StringSink(plaintext),
							CryptoPP::StreamTransformationFilter::PKCS_PADDING
						)
					)
				);
			} catch (...) {
				continue;
			}

			/*
			bool ok = true;
			for (auto i : plaintext) {
				ok &= i >= 32 && i < 127;
			}

			if (ok) {
				std::cout << key << std::endl;
				std::cout << plaintext << std::endl;
			}
			*/

			std::cout << key << std::endl;
			std::cout << plaintext << std::endl;
		}
	}

	return 0;
}
