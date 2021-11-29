#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto import Random
import secrets


def pkcs7_padding(m):
    # There is padding and there is PKCS#7 padding 🤮
    l = len(m)
    pad_len = 16 - (l % 16)
    pad_len_hex = pad_len.to_bytes(1, byteorder="little")
    padding = bytes([pad_len_hex[0] for i in range(0, pad_len)])

    return m+padding


# Prevent IV replays
iv_list = set()


def encrypt(iv, m):

    if iv in iv_list:
        print("ERROR: REPLAYED IV")
        return bytes([])

    iv_list.add(iv)

    m = pkcs7_padding(m)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(m)


def get_iv():
    return Random.new().read(AES.block_size)


KEY = open('key.txt', 'rb').read()

# stdin/stdout version
if __name__ == "__main__":
    while True:
        iv = get_iv()
        print("IV for encryption (hex):")
        print(iv.hex())
        print("Enter message (as a hex bytes string):")
        x = bytes.fromhex(input())
        # print("Message: " + str(x) + "\n")
        print("Ciphertext (hex): " + str(encrypt(iv, x).hex()) + "\n")
