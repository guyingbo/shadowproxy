import socket
import iofree


def read_addr():
    atyp = yield from iofree.read(1)
    if atyp == b"\x01":  # IPV4
        data = yield from iofree.read(4)
        host = socket.inet_ntoa(data)
    elif atyp == b"\x04":  # IPV6
        data = yield from iofree.read(16)
        host = socket.inet_ntop(socket.AF_INET6, data)
    elif atyp == b"\x03":  # hostname
        data = yield from iofree.read(1)
        data += yield from iofree.read(data[0])
        host = data[1:].decode("ascii")
    else:
        raise Exception(f"unknown atyp: {atyp}")
    port, = yield from iofree.read_struct("!H")
    return (host, port)


@iofree.parser
def socks5_request(auth=False):
    parser = yield from iofree.get_parser()
    ver, nmethods = yield from iofree.read_struct("!BB")
    assert ver == 5, f"bad socks version: {ver}"
    assert nmethods != 0, f"nmethods can't be 0"
    methods = yield from iofree.read(nmethods)
    if auth and b"\x02" not in methods:
        parser.write(b"\x05\x02")
        raise Exception("server needs authentication")
    elif b"\x00" not in methods:
        parser.write(b"\x05\x00")
        raise Exception("method not support")
    if auth:
        parser.write(b"\x05\x02")
        auth_ver, username_length = yield from iofree.read_struct("!BB")
        assert auth_ver == 1, f"invalid auth version {auth_ver}"
        username = yield from iofree.read(username_length)
        password_length = (yield from iofree.read(1))[0]
        password = yield from iofree.read(password_length)
        if (username, password) != auth:
            parser.write(b"\x01\x01")
            raise Exception("authenticate failed")
        else:
            parser.write(b"\x01\x00")
    else:
        parser.write(b"\x05\x00")
    ver, cmd, rsv = yield from iofree.read_struct("!BBB")
    if cmd == 1:  # connect
        pass
    elif cmd == 2:  # bind
        raise Exception("doesn't support bind yet")
    elif cmd == 3:  # associate
        raise Exception("doesn't support associate yes")
    else:
        raise Exception(f"unknown cmd: {cmd}")
    target_addr = yield from read_addr()
    return target_addr, cmd


@iofree.parser
def socks5_response(auth):
    data = yield from iofree.read(2)
    assert data[0] == 5, f"bad socks version: {data[0]}"
    method = data[1]
    assert method in (0, 2), f"bad method {data[1]}"
    if auth:
        auth_ver, status = yield from iofree.read_struct("!BB")
        assert auth_ver == 1, f"invalid auth version {auth_ver}"
        assert status == 0, f"invalid status {status}"
    data = yield from iofree.read(3)
    assert data[0] == 5, f"bad socks version: {data[0]}"
    assert data[1] == 0, f"failed REP with code: {data[1]}"
    bind_addr = yield from read_addr()
    return bind_addr


@iofree.parser
def socks4_response():
    res, cd, port, ip_bytes = yield from iofree.read_struct("!BBH4s")
    assert res == 0, f"bad socks response: {res}"
    assert cd == 90, f"bad CD code: {cd}"
    ip = socket.inet_ntoa(ip_bytes)
    return (ip, port)


@iofree.parser
def socks4_request():
    vn, cd, port, dst_ip = yield from iofree.read_struct("!BBH4s")
    assert vn == 4, f"bad socks version: {vn}"
    assert cd == 1, f"invalid command {cd}"
    user_id = yield from iofree.read_until(b"\x00", return_tail=False)
    del user_id
    if dst_ip[:3] == b"\x00\x00\x00":
        hostname = yield from iofree.read_until(b"\x00", return_tail=False)
    else:
        hostname = socket.inet_ntoa(dst_ip)
    return (hostname, port)
