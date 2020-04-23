import os
import random

from shadowproxy.ciphers import StreamCipher, ciphers


def test_ciphers():
    for Cipher in ciphers.values():
        cipher = Cipher("password")
        if isinstance(cipher, StreamCipher):
            iv, encrypt = cipher.make_encrypter()
            decrypt = cipher.make_decrypter(iv)
            for i in range(100):
                plaintext = os.urandom(random.randint(1, 100))
                ciphertext = encrypt(plaintext)
                assert decrypt(ciphertext) == plaintext
        else:
            salt, encrypt = cipher.make_encrypter()
            decrypt = cipher.make_decrypter(salt)

            for i in range(100):
                plaintext = os.urandom(random.randint(1, 100))
                ciphertext, tag = encrypt(plaintext)
                assert decrypt(ciphertext, tag) == plaintext
