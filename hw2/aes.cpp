#include <iostream>
#include <fstream>
#include <cassert>
#ifdef DEBUG
#include <cassert>
#endif

#include "cryptopp/modes.h"
#include "cryptopp/rijndael.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"

#ifdef DEBUG
const std::string TEST_IV = "0000000000000000";
const std::string TEST_KEY = "1234567890ABCDEF";
const std::string TEST_PLAINTEXT = "Hello World!";
const std::string TEST_CIPHERTEXT_CFB = "36DB745B3B6DA69ABF5FEB23";
const std::string TEST_CIPHERTEXT_CBC = "4C855D6317608F8DD39461E5BCC940B8";
const std::string TEST_CIPHERTEXT_ECB = "D523326C27EE0F2165C7696B36F2688E";
#endif

const std::string PLAINTEXT = "AES is the US block cipher standard.";
const std::string KEY = "keyis84932731830";
const std::string IV_0 = "0000000000000000";
const std::string IV_9 = "9999999999999999";


int main() {
#ifdef DEBUG
	// {{{
	/*
	 * AES
	 * CFB Mode (feedback size: 4 bytes)
	 * No Padding
	 */
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption test_aes_cfb;
	std::string test_ciphertext_cfb;

	CryptoPP::AlgorithmParameters test_params_cfb = CryptoPP::MakeParameters
		(CryptoPP::Name::FeedbackSize(), 4)
		(CryptoPP::Name::IV(), reinterpret_cast<const CryptoPP::byte*>(TEST_IV.data()));

	test_aes_cfb.SetKey(
		reinterpret_cast<const CryptoPP::byte*>(TEST_KEY.data()),
		TEST_KEY.size(),
		test_params_cfb
	);

	CryptoPP::StringSource ss_cfb(
		TEST_PLAINTEXT,
		true,
		new CryptoPP::StreamTransformationFilter(
			test_aes_cfb,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(test_ciphertext_cfb)
			),
			CryptoPP::StreamTransformationFilter::NO_PADDING
		)
	);

	assert(test_ciphertext_cfb == TEST_CIPHERTEXT_CFB);


	/*
	 * AES
	 * CBC Mode
	 * Zero Padding
	 */
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption test_aes_cbc;
	std::string test_ciphertext_cbc;

	test_aes_cbc.SetKeyWithIV(
		reinterpret_cast<const CryptoPP::byte*>(TEST_KEY.data()),
		TEST_KEY.size(),
		reinterpret_cast<const CryptoPP::byte*>(TEST_IV.data())
	);

	CryptoPP::StringSource ss_cbc(
		TEST_PLAINTEXT,
		true,
		new CryptoPP::StreamTransformationFilter(
			test_aes_cbc,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(test_ciphertext_cbc)
			),
			CryptoPP::StreamTransformationFilter::ZEROS_PADDING
		)
	);

	assert(test_ciphertext_cbc == TEST_CIPHERTEXT_CBC);


	/*
	 * AES
	 * ECB Mode
	 * PKCS#7 Padding
	 */
	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption test_aes_ecb;
	std::string test_ciphertext_ecb;

	test_aes_ecb.SetKey(
		reinterpret_cast<const CryptoPP::byte*>(TEST_KEY.data()),
		TEST_KEY.size()
	);

	CryptoPP::StringSource ss_ecb(
		TEST_PLAINTEXT,
		true,
		new CryptoPP::StreamTransformationFilter(
			test_aes_ecb,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(test_ciphertext_ecb)
			),
			CryptoPP::StreamTransformationFilter::PKCS_PADDING
		)
	);

	assert(test_ciphertext_ecb == TEST_CIPHERTEXT_ECB);
	// }}}
#endif

	/*
	 * AES
	 * CFB Mode (feedback size: 4 bytes)
	 * No Padding
	 * IV: 0000000000000000
	 */
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption aes_cfb;
	std::string ciphertext_cfb;

	CryptoPP::AlgorithmParameters params_cfb = CryptoPP::MakeParameters
		(CryptoPP::Name::FeedbackSize(), 4)
		(CryptoPP::Name::IV(), reinterpret_cast<const CryptoPP::byte*>(IV_0.data()));

	aes_cfb.SetKey(
		reinterpret_cast<const CryptoPP::byte*>(KEY.data()),
		KEY.size(),
		params_cfb
	);

	CryptoPP::StringSource ss_cfb(
		PLAINTEXT,
		true,
		new CryptoPP::StreamTransformationFilter(
			aes_cfb,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(ciphertext_cfb)
			),
			CryptoPP::StreamTransformationFilter::NO_PADDING
		)
	);

	// std::cout << ciphertext_cfb << std::endl;


	/*
	 * AES
	 * CBC Mode
	 * Zero Padding
	 * IV: 0000000000000000
	 */
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes_cbc_0;
	std::string ciphertext_cbc_0;

	aes_cbc_0.SetKeyWithIV(
		reinterpret_cast<const CryptoPP::byte*>(KEY.data()),
		KEY.size(),
		reinterpret_cast<const CryptoPP::byte*>(IV_0.data())
	);

	CryptoPP::StringSource ss_cbc_0(
		PLAINTEXT,
		true,
		new CryptoPP::StreamTransformationFilter(
			aes_cbc_0,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(ciphertext_cbc_0)
			),
			CryptoPP::StreamTransformationFilter::ZEROS_PADDING
		)
	);

	// std::cout << ciphertext_cbc_0 << std::endl;


	/*
	 * AES
	 * CBC Mode
	 * PKCS#7 Padding
	 * IV: 9999999999999999
	 */
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes_cbc_9;
	std::string ciphertext_cbc_9;

	aes_cbc_9.SetKeyWithIV(
		reinterpret_cast<const CryptoPP::byte*>(KEY.data()),
		KEY.size(),
		reinterpret_cast<const CryptoPP::byte*>(IV_9.data())
	);

	CryptoPP::StringSource ss_cbc_9(
		PLAINTEXT,
		true,
		new CryptoPP::StreamTransformationFilter(
			aes_cbc_9,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(ciphertext_cbc_9)
			),
			CryptoPP::StreamTransformationFilter::PKCS_PADDING
		)
	);

	// std::cout << ciphertext_cbc_9 << std::endl;


	/*
	 * AES
	 * ECB Mode
	 * PKCS#7 Padding
	 */
	CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aes_ecb;
	std::string ciphertext_ecb;

	aes_ecb.SetKey(
		reinterpret_cast<const CryptoPP::byte*>(KEY.data()),
		KEY.size()
	);

	CryptoPP::StringSource ss_ecb(
		PLAINTEXT,
		true,
		new CryptoPP::StreamTransformationFilter(
			aes_ecb,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(ciphertext_ecb)
			),
			CryptoPP::StreamTransformationFilter::PKCS_PADDING
		)
	);

	// std::cout << ciphertext_ecb << std::endl;

	std::ofstream fout("./aes-out.txt");

	fout << ciphertext_cfb << std::endl
		 << ciphertext_cbc_0 << std::endl
		 << ciphertext_cbc_9 << std::endl
		 << ciphertext_ecb << std::endl;
	
	return 0;
}
