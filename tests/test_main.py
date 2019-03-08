import curio
import socket
import pytest
from ipaddress import ip_address
from shadowproxy.utils import (
    is_global,
    pack_addr,
    unpack_addr,
    human_speed,
    human_bytes,
    open_connection,
)


def test_is_global():
    assert not is_global("127.0.0.1")
    assert not is_global("192.168.20.168")
    assert is_global("211.13.20.168")
    assert is_global("google.com")


def test_pack_addr():
    assert pack_addr(("127.0.0.1", 8080)) == b"\x01\x7f\x00\x00\x01\x1f\x90"
    ipv6 = "1050:0:0:0:5:600:300c:326b"
    data = pack_addr((ipv6, 80))
    assert ip_address(unpack_addr(data)[0][0]) == ip_address(ipv6)


def test_unpack_addr():
    addr = ("232.32.9.86", 49238)
    assert unpack_addr(pack_addr(addr))[0] == addr
    addr = ("google.com", 80)
    assert unpack_addr(pack_addr(addr))[0] == addr
    with pytest.raises(Exception):
        unpack_addr(b"\x02")


def test_human_bytes():
    assert human_bytes(10) == "10Bytes"
    assert human_bytes(1025) == "1.0KB"
    assert human_bytes(1024 * 1024 + 1) == "1.0MB"


def test_human_speed():
    assert human_speed(10) == "10 B/s"
    assert human_speed(1024) == "1.0 KB/s"
    assert human_speed(1024 * 1024 + 1) == "1.0 MB/s"


def test_open_connection():
    with pytest.raises(socket.gaierror):
        curio.run(open_connection("does-not-exists.com", 80))
