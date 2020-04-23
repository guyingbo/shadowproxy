import os
import secrets

from shadowproxy.ciphers import AES128GCM, AES256CFB
from shadowproxy.proxies.aead.parser import aead_reader
from shadowproxy.proxies.shadowsocks.parser import ss_reader


def test_ss():
    cipher = AES256CFB(secrets.token_urlsafe(20))
    iv, encrypt = cipher.make_encrypter()
    length = len(iv) // 2
    parser = ss_reader.parser(cipher)
    parser.send(iv[:length])
    assert parser.read_output_bytes() == b""
    data = os.urandom(20)
    parser.send(iv[length:] + encrypt(data))
    assert parser.read_output_bytes() == data


def test_ss2():
    cipher = AES256CFB(secrets.token_urlsafe(20))
    iv, encrypt = cipher.make_encrypter()
    parser = ss_reader.parser(cipher)
    parser.send(iv)
    assert parser.read_output_bytes() == b""
    assert parser.read_output_bytes() == b""
    data = os.urandom(20)
    parser.send(encrypt(data))
    assert parser.read_output_bytes() == data


def test_aead():
    cipher = AES128GCM(secrets.token_urlsafe(20))
    salt, encrypt = cipher.make_encrypter()
    length = len(salt) // 2
    aead = aead_reader.parser(cipher)
    aead.send(salt[:length])
    assert aead.read_output_bytes() == b""
    data = os.urandom(20)
    aead.send(salt[length:] + b"".join(encrypt(len(data).to_bytes(2, "big"))))
    assert aead.read_output_bytes() == b""
    aead.send(b"".join(encrypt(data)))
    assert aead.read_output_bytes() == data
