CC=g++
CFLAGS=-std=c++17 -O2 -Wall -Wextra -Wshadow
DEBUG=-DDEBUG

LIB_CRYPTOPP=-I.. ../cryptopp/libcryptopp.a

rsa: rsa.cpp
	$(CC) $(CFLAGS) rsa.cpp -o rsa $(LIB_CRYPTOPP)

rsa-debug: rsa.cpp
	$(CC) $(CFLAGS) $(DEBUG) rsa.cpp -o rsa $(LIB_CRYPTOPP)

rsa-onsite: rsa-onsite.cpp
	$(CC) $(CFLAGS) rsa-onsite.cpp -o rsa $(LIB_CRYPTOPP)

zip: rsa.cpp out.txt
	zip $(ID).zip rsa.cpp out.txt

.PHONY: clean
clean:
	rm rsa $(ID).zip
