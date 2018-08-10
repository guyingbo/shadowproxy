import os
import random
from shadowproxy.ciphers import AES128GCM, AES192GCM, AES256GCM


def test_ciphers():
    ciphers = [AES128GCM("password"), AES192GCM("password"), AES256GCM("password")]
    for cipher in ciphers:
        salt, encrypt = cipher.make_encrypter()
        decrypt = cipher.make_decrypter(salt)

        for i in range(100):
            plaintext = os.urandom(random.randint(1, 100))
            ciphertext, tag = encrypt(plaintext)
            assert decrypt(ciphertext, tag) == plaintext
