CC=g++
CFLAGS=-std=c++17 -O2
DEBUG=-DDEBUG -Wall -Wextra -Wshadow

LIB_CRYPTOPP=-I.. ../cryptopp/libcryptopp.a

des: des.cpp
	$(CC) $(CFLAGS) des.cpp -o des

des-debug: des.cpp
	$(CC) $(CFLAGS) $(DEBUG) des.cpp -o des

des-onsite: des-onsite.cpp
	$(CC) $(CFLAGS) des-onsite.cpp -o des

aes: aes.cpp
	$(CC) $(CFLAGS) aes.cpp -o aes $(LIB_CRYPTOPP)

aes-debug: aes.cpp
	$(CC) $(CFLAGS) $(DEBUG) aes.cpp -o aes $(LIB_CRYPTOPP)

aes-onsite: aes-onsite.cpp
	$(CC) $(CFLAGS) aes-onsite.cpp -o aes $(LIB_CRYPTOPP)

.PHONY: clean
clean:
	rm des aes
