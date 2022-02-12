from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from string import printable

iv = b'0' * 16
ct = bytes.fromhex("AC45D78068C2BD87C3F50DEC9F898260");

for i in range(ord('0'), ord('9') + 1):
    for j in range(ord('0'), ord('9') + 1):
        key = (chr(i) + chr(j) + '0' * 14).encode()
        aes = AES.new(key, AES.MODE_CBC, iv=iv)

        try:
            pt = unpad(aes.decrypt(ct), 16)
        except:
            continue

        if all(i in list(printable.encode()) for i in pt):
            print(pt.decode())
