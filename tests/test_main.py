import shadowproxy


def test_is_local():
    assert shadowproxy.is_local("127.0.0.1") is True
    assert shadowproxy.is_local("192.168.20.168") is True
    assert shadowproxy.is_local("211.13.20.168") is False


def test_pack_addr():
    assert shadowproxy.pack_addr(("127.0.0.1", 8080)) == b"\x01\x7f\x00\x00\x01\x1f\x90"


def test_unpack_addr():
    addr = ("232.32.9.86", 49238)
    assert shadowproxy.unpack_addr(shadowproxy.pack_addr(addr))[0] == addr


def test_uri_compile():
    ns = shadowproxy.uri_compile("socks://:8527", True)
    assert ns.scheme == "socks"
    assert ns.proto == shadowproxy.SocksConnection
    assert ns.kw["host"] == ""
    assert ns.kw["port"] == 8527
    ns = shadowproxy.uri_compile("ss://aes-256-cfb:passwd@:8527", False)
    assert ns.scheme == "ss"
    assert ns.proto == shadowproxy.SSClient
