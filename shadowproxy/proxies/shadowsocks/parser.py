import socket
import iofree


@iofree.parser
def ss_reader(cipher):
    iv = yield from iofree.read(cipher.IV_SIZE)
    decrypt = cipher.make_decrypter(iv)
    while True:
        data = yield from iofree.read_more()
        yield from iofree.write(decrypt(data))


@iofree.parser
def addr_reader():
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
    data_port = yield from iofree.read(2)
    port = int.from_bytes(data_port, "big")
    return (host, port), atyp + data + data_port
