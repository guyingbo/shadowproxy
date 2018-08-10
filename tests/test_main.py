from shadowproxy.utils import is_local, pack_addr, unpack_addr


def test_is_local():
    assert is_local("127.0.0.1") is True
    assert is_local("192.168.20.168") is True
    assert is_local("211.13.20.168") is False


def test_pack_addr():
    assert pack_addr(("127.0.0.1", 8080)) == b"\x01\x7f\x00\x00\x01\x1f\x90"


def test_unpack_addr():
    addr = ("232.32.9.86", 49238)
    assert unpack_addr(pack_addr(addr))[0] == addr
