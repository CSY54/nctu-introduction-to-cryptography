CC=g++
CFLAGS=-g -std=c++17 -Ofast
DEBUG=-Wall -Wextra -Wshadow # -DDEBUG

LIB_CRYPTOPP=-I.. ../cryptopp/libcryptopp.a
LNK=-lpthread

hashchain: hashchain.cpp
	$(CC) $(CFLAGS) hashchain.cpp -o hashchain $(LIB_CRYPTOPP)

hashchain-debug: hashchain.cpp
	$(CC) $(CFLAGS) $(DEBUG) hashchain.cpp -o hashchain $(LIB_CRYPTOPP)

hashchain-thread: hashchain-thread.cpp
	$(CC) $(CFLAGS) hashchain-thread.cpp -o hashchain-thread $(LIB_CRYPTOPP) $(LNK)

hashchain-thread-debug: hashchain-thread.cpp
	$(CC) $(CFLAGS) $(DEBUG) hashchain-thread.cpp -o hashchain-thread $(LIB_CRYPTOPP) $(LNK)

zip: hashchain.cpp out.txt
	zip $(ID).zip hashchain.cpp out.txt

.PHONY: clean
clean:
	rm hashchain hashchain-thread $(ID).zip
