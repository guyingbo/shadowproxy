import abc
import os
from hashlib import md5, sha1

import hkdf
from Crypto.Cipher import AES, ARC4, ChaCha20, ChaCha20_Poly1305, Salsa20


class BaseCipher:
    def __init__(self, password: str):
        self.master_key = self._get_key(password.encode("ascii", "ignore"))

    def _get_key(self, password: bytes, salt: bytes = b"") -> bytes:
        keybuf = []
        while len(b"".join(keybuf)) < self.KEY_SIZE:
            keybuf.append(
                md5((keybuf[-1] if keybuf else b"") + password + salt).digest()
            )
        return b"".join(keybuf)[: self.KEY_SIZE]


class AEADCipher(BaseCipher, metaclass=abc.ABCMeta):
    info = b"ss-subkey"
    is_stream_cipher = False
    PACKET_LIMIT = 0x3FFF

    @property
    @abc.abstractmethod
    def KEY_SIZE(self):
        ""

    @property
    @abc.abstractmethod
    def SALT_SIZE(self):
        ""

    @property
    @abc.abstractmethod
    def NONCE_SIZE(self):
        ""

    @property
    @abc.abstractmethod
    def TAG_SIZE(self):
        ""

    def _derive_subkey(self, salt: bytes) -> bytes:
        return hkdf.Hkdf(salt, self.master_key, sha1).expand(self.info, self.KEY_SIZE)

    def random_salt(self) -> bytes:
        return os.urandom(self.SALT_SIZE)

    def make_encrypter(self, salt: bytes = None) -> (bytes, bytes):
        counter = 0
        salt = salt if salt is not None else self.random_salt()
        subkey = self._derive_subkey(salt)

        def encrypt(plaintext: bytes) -> bytes:
            nonlocal counter
            nonce = counter.to_bytes(self.NONCE_SIZE, "little")
            counter += 1
            encrypter = self.new_cipher(subkey, nonce)
            if len(plaintext) <= self.PACKET_LIMIT:
                return encrypter.encrypt_and_digest(plaintext)
            else:
                with memoryview(plaintext) as data:
                    return encrypter.encrypt_and_digest(
                        data[: self.PACKET_LIMIT]
                    ) + encrypt(data[self.PACKET_LIMIT :])

        return salt, encrypt

    def make_decrypter(self, salt: bytes):
        counter = 0
        subkey = self._derive_subkey(salt)

        def decrypt(ciphertext: bytes, tag: bytes) -> bytes:
            nonlocal counter
            nonce = counter.to_bytes(self.NONCE_SIZE, "little")
            counter += 1
            decrypter = self.new_cipher(subkey, nonce)
            return decrypter.decrypt_and_verify(ciphertext, tag)

        return decrypt

    @abc.abstractmethod
    def new_cipher(self, subkey: bytes, nonce: bytes):
        ""


class AES128GCM(AEADCipher):
    KEY_SIZE = 16
    SALT_SIZE = 16
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def new_cipher(self, subkey: bytes, nonce: bytes):
        return AES.new(subkey, AES.MODE_GCM, nonce=nonce, mac_len=self.TAG_SIZE)


class AES192GCM(AES128GCM):
    KEY_SIZE = 24
    SALT_SIZE = 24
    NONCE_SIZE = 12
    TAG_SIZE = 16


class AES256GCM(AES128GCM):
    KEY_SIZE = 32
    SALT_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16


class ChaCha20IETFPoly1305(AEADCipher):
    KEY_SIZE = 32
    SALT_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def new_cipher(self, subkey: bytes, nonce: bytes):
        return ChaCha20_Poly1305.new(key=subkey, nonce=nonce)


class StreamCipher(BaseCipher, metaclass=abc.ABCMeta):
    is_stream_cipher = True

    @property
    @abc.abstractmethod
    def KEY_SIZE(self):
        ""

    @property
    @abc.abstractmethod
    def IV_SIZE(self):
        ""

    def random_iv(self):
        return os.urandom(self.IV_SIZE)

    def make_encrypter(self, iv: bytes = None):
        iv = iv if iv is not None else self.random_iv()
        cipher = self.new_cipher(self.master_key, iv)

        def encrypt(plaintext: bytes) -> bytes:
            return cipher.encrypt(plaintext)

        return iv, encrypt

    def make_decrypter(self, iv):
        cipher = self.new_cipher(self.master_key, iv)

        def decrypt(ciphertext: bytes) -> bytes:
            return cipher.decrypt(ciphertext)

        return decrypt

    @abc.abstractmethod
    def new_cipher(self, key: bytes, iv: bytes):
        ""


class AES256CFB(StreamCipher):
    KEY_SIZE = 32
    IV_SIZE = 16

    def new_cipher(self, key: bytes, iv: bytes):
        return AES.new(key, mode=AES.MODE_CFB, iv=iv, segment_size=128)


class AES128CFB(AES256CFB):
    KEY_SIZE = 16


class AES192CFB(AES256CFB):
    KEY_SIZE = 24


class ChaCha20Cipher(StreamCipher):
    KEY_SIZE = 32
    IV_SIZE = 8

    def new_cipher(self, key: bytes, iv: bytes):
        return ChaCha20.new(key=key, nonce=iv)


class Salsa20Cipher(StreamCipher):
    KEY_SIZE = 32
    IV_SIZE = 8

    def new_cipher(self, key: bytes, iv: bytes):
        return Salsa20.new(key=key, nonce=iv)


class RC4Cipher(StreamCipher):
    KEY_SIZE = 16
    IV_SIZE = 0

    def new_cipher(self, key: bytes, iv: bytes):
        return ARC4.new(key=key)


ciphers = {
    "aes-256-cfb": AES256CFB,
    "aes-128-cfb": AES128CFB,
    "aes-192-cfb": AES192CFB,
    "chacha20": ChaCha20Cipher,
    "salsa20": Salsa20Cipher,
    "rc4": RC4Cipher,
    "aes-256-gcm": AES256GCM,
    "aes-192-gcm": AES192GCM,
    "aes-128-gcm": AES128GCM,
    "chacha20-ietf-poly1305": ChaCha20IETFPoly1305,
}
