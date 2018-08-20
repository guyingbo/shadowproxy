import ohneio
import struct
import socket


def read_addr():
    atyp = yield from ohneio.read(1)
    if atyp == b"\x01":  # IPV4
        data = yield from ohneio.read(4)
        host = socket.inet_ntoa(data)
    elif atyp == b"\x04":  # IPV6
        data = yield from ohneio.read(16)
        host = socket.inet_ntop(socket.AF_INET6, data)
    elif atyp == b"\x03":  # hostname
        data = yield from ohneio.read(1)
        data += yield from ohneio.read(data[0])
        host = data[1:].decode("ascii")
    else:
        raise Exception(f"unknow atyp: {atyp}")
    data_port = yield from ohneio.read(2)
    port = int.from_bytes(data_port, "big")
    return (host, port)


@ohneio.protocol
def Socks5RequestParser(auth=False):
    ver, nmethods = struct.unpack("!BB", (yield from ohneio.read(2)))
    assert ver == 5, f"bad socks version: {ver}"
    assert nmethods != 0, f"nmethods can't be 0"
    methods = yield from ohneio.read(nmethods)
    if auth and b"\x02" not in methods:
        yield from ohneio.write(b"\x05\xff")
        raise Exception("server needs auth")
    elif b"\x00" not in methods:
        yield from ohneio.write(b"\x05\x00")
        raise Exception("method not support")
    if auth:
        yield from ohneio.write(b"\x05\x02")
        auth_ver, username_length = struct.unpack("!BB", (yield from ohneio.read(2)))
        assert auth_ver == 1
        username = yield from ohneio.read(username_length)
        password_length = (yield from ohneio.read(1))[0]
        password = yield from ohneio.read(password_length)
        if (username, password) != auth:
            yield from ohneio.write(b"\x01\x01")
            raise Exception("auth failed")
        else:
            yield from ohneio.write(b"\x01\x00")
    else:
        yield from ohneio.write(b"\x05\x00")
    ver, cmd, rsv = struct.unpack("!BBB", (yield from ohneio.read(3)))
    if cmd == 1:  # connect
        pass
    elif cmd == 2:  # bind
        raise Exception("doesn't support yet")
    elif cmd == 3:  # associate
        pass
    else:
        raise Exception(f"unknown cmd: {cmd}")
    target_addr = yield from read_addr()
    return target_addr, cmd


@ohneio.protocol
def Socks5ResponseParser():
    data = yield from ohneio.read(2)
    assert data[0] == 5, f"bad socks version: {data[0]}"
    method = data[1]
    assert method in (0, 2), f"bad method {data[1]}"
    data = yield from ohneio.read(3)
    assert data[0] == 5, f"bad socks version: {data[0]}"
    assert data[1] == 0, f"failed REP with code: {data[1]}"
    bind_addr = yield from read_addr()
    return bind_addr


@ohneio.protocol
def Socks4ResponseParser():
    data = memoryview((yield from ohneio.read(8)))
    assert data[0] == 0, f"bad socks version: {data[0]}"
    assert data[1] == 90, f"bad CD code: {data[1]}"
    port = int.from_bytes(data[2:4], "big")
    ip = socket.inet_ntoa(data[4:])
    return (ip, port)
