from Crypto.PublicKey import RSA


# Part 1
def encrypt(n, e, plaintext):
    return hex(pow(plaintext, e, n))[2:]


# Part 1 - Debug
n = 0xc963f963d93559ff
e = 0x11
plaintext = int.from_bytes(b'ElGamal', byteorder='big')
ciphertext = encrypt(n, e, plaintext)
assert ciphertext == '6672e7d4a8786631'


# Part 1 - Case 1
n = 0x04823f9fe38141d93f1244be161b20f
e = 0x11
plaintext = int.from_bytes(b'Hello World!', byteorder='big')
ciphertext = encrypt(n, e, plaintext)
print(ciphertext)


# Part 1 - Case 2
n = 0x9711ea5183d50d6a91114f1d7574cd52621b35499b4d3563ec95406a994099c9
e = 0x10001
plaintext = int.from_bytes(b'RSA is public key.', byteorder='big')
ciphertext = encrypt(n, e, plaintext)
print(ciphertext)


# Part 2
def brute(n, e, d, ciphertext):
    while True:
        try:
            # just to validate key
            RSA.construct((n, e, d))

            ciphertext = bytes.fromhex(hex(pow(ciphertext, d, n))[2:]).decode()

            return (d, ciphertext)

        except ValueError:
            d += 1


# Part 2 - Debug
n = 0xc45350fa19fa8d93
e = 0x11
partial_d = 0x454a950c5bcbaa40
ciphertext = 0xa4a59490b843eea0
d, plaintext = brute(n, e, partial_d, ciphertext)
assert(d == 0x454a950c5bcbaa41)
assert(plaintext == 'secrecy')


# Part 2 - Case 1
n = 0xc4b361851de35f080d3ca7352cbf372d
e = 0x1d35
partial_d = 0x53a0a95b089cf23adb5cc73f0700000
partial_d = 6947507880447813262923413425621498450
ciphertext = 0xa02d51d0e87efe1defc19f3ee899c31d
d, plaintext = brute(n, e, partial_d, ciphertext)
print(hex(d)[2:])
print(plaintext)
