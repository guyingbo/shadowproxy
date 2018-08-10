from shadowproxy.cli import get_server
from shadowproxy.proxies import shadowsocks


def test_get_server():
    server, bind_addr, scheme = get_server("socks://:8527")
    assert scheme == "socks"
    assert bind_addr == ("", 8527)
    ns = get_server("ss://YWVzLTI1Ni1jZmI6cGFzc3dk@:8527", True)
    assert ns.bind_addr == ("", 8527)
    assert ns.ClientClass == shadowsocks.SSClient
