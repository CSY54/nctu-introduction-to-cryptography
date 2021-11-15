#include <iostream>
#include <fstream>
#include <cassert>

#include "cryptopp/rsa.h"
#include "cryptopp/misc.h"
#include "cryptopp/osrng.h"

CryptoPP::Integer pow(CryptoPP::Integer a, CryptoPP::Integer b, CryptoPP::Integer m) {
	CryptoPP::Integer res("1");
	while (b != 0) {
		if (b % 2 == 1) {
			res = (res * a) % m;
		}
		b >>= 1;
		a = (a * a) % m;
	}
	return res;
}

bool is_valid(CryptoPP::Integer n) {
	CryptoPP::Integer sum("0");
	while (n != 0) {
		sum += n % 10;
		sum %= 10;
		n /= 10;
	}
	return sum == 9;
}

int main() {
	CryptoPP::Integer n("253963006250652707627402859040685100389");
	CryptoPP::Integer e("65537");
	CryptoPP::Integer d("42772482296155483517134936268603049473");
	CryptoPP::Integer partial_ct("31639169974475525248366103533531939340");

	for (int i = 0; i < 10; i++) {
		CryptoPP::Integer ct = partial_ct + CryptoPP::Integer(i);

		CryptoPP::Integer pt = pow(ct, d, n);

		if (is_valid(pt)) {
			std::cout << pt << std::endl;
		}
	}

	return 0;
}
