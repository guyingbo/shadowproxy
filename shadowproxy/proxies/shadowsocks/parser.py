import ohneio
import socket


@ohneio.protocol
def SSParser(cipher):
    iv = yield from ohneio.read(cipher.IV_SIZE)
    decrypt = cipher.make_decrypter(iv)
    while True:
        data = yield from ohneio.read()
        if not data:
            yield from ohneio.wait()
            continue
        data = decrypt(data)
        yield from ohneio.write(data)


@ohneio.protocol
def AddrParser():
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
    return (host, port), atyp + data + data_port
