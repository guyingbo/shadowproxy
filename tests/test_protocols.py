import os
import secrets
from shadowproxy.ciphers import AES128GCM, AES256CFB
from shadowproxy.proxies.shadowsocks.parser import AddrParser, SSParser
from shadowproxy.proxies.aead.parser import AEADParser
from shadowproxy.utils import pack_addr


def test_ss():
    cipher = AES256CFB(secrets.token_urlsafe(20))
    iv, encrypt = cipher.make_encrypter()
    length = len(iv) // 2
    reader = SSParser(cipher)
    reader.send(iv[:length])
    assert reader.read() == b""
    data = os.urandom(20)
    reader.send(iv[length:] + encrypt(data))
    assert reader.read() == data


def test_ss2():
    cipher = AES256CFB(secrets.token_urlsafe(20))
    iv, encrypt = cipher.make_encrypter()
    reader = SSParser(cipher)
    reader.send(iv)
    assert reader.read() == b""
    assert reader.read() == b""
    data = os.urandom(20)
    reader.send(encrypt(data))
    assert reader.read() == data


def test_aead():
    cipher = AES128GCM(secrets.token_urlsafe(20))
    salt, encrypt = cipher.make_encrypter()
    length = len(salt) // 2
    aead = AEADParser(cipher).new()
    aead.send(salt[:length])
    assert aead.read() == b""
    data = os.urandom(20)
    aead.send(salt[length:] + b"".join(encrypt(len(data).to_bytes(2, "big"))))
    assert aead.read() == b""
    aead.send(b"".join(encrypt(data)))
    assert aead.read() == data


def test_addr_reader():
    addrs = (
        ("127.0.0.1", 8000),
        ("example.com", 7999),
        ("1050::5:600:300c:326b", 8889),
    )
    for addr in addrs:
        addr_bytes = pack_addr(addr)
        addr_reader = AddrParser()
        length = len(addr_bytes) // 2
        addr_reader.send(addr_bytes[:length])
        assert not addr_reader.has_result
        tail = os.urandom(10)
        addr_reader.send(addr_bytes[length:] + tail)
        assert addr_reader.has_result
        new_addr, _ = addr_reader.get_result()
        assert new_addr == addr
