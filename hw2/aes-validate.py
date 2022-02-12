from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

PLAINTEXT = b'AES is the US block cipher standard.';
KEY = b'keyis84932731830';
IV_0 = b'0000000000000000';
IV_9 = b'9999999999999999';

aes_cfb = AES.new(KEY, AES.MODE_CFB, iv=IV_0, segment_size=32)
ciphertext_cfb = aes_cfb.encrypt(PLAINTEXT)
print(ciphertext_cfb.hex().upper())

aes_cbc_0 = AES.new(KEY, AES.MODE_CBC, iv=IV_0)
padded_plaintext = PLAINTEXT + b'\x00' * (16 - len(PLAINTEXT) % 16)
ciphertext_cbc_0 = aes_cbc_0.encrypt(padded_plaintext)
print(ciphertext_cbc_0.hex().upper())

aes_cbc_9 = AES.new(KEY, AES.MODE_CBC, iv=IV_9)
ciphertext_cbc_9 = aes_cbc_9.encrypt(pad(PLAINTEXT, 16))
print(ciphertext_cbc_9.hex().upper())

aes_ecb = AES.new(KEY, AES.MODE_ECB)
ciphertext_ecb = aes_ecb.encrypt(pad(PLAINTEXT, 16))
print(ciphertext_ecb.hex().upper())
