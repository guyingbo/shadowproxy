import ohneio
import struct
import socket


class AEADReader:
    def __init__(self, cipher):
        self.cipher = cipher

    @ohneio.protocol
    def new(self):
        salt = yield from ohneio.read(self.cipher.SALT_SIZE)
        self.decrypt = self.cipher.make_decrypter(salt)
        while True:
            payload = yield from self.read_some()
            yield from ohneio.write(payload)

    def read_some(self):
        chunk0 = yield from ohneio.read(2 + self.cipher.TAG_SIZE)
        data = memoryview(chunk0)
        length_bytes = self.decrypt(data[:2], data[2:])
        length, = struct.unpack_from("!H", length_bytes)
        if length != length & 0x3FFF:
            raise Exception("invalid length")
        chunk1 = yield from ohneio.read(length + self.cipher.TAG_SIZE)
        data = memoryview(chunk1)
        payload = self.decrypt(data[:length], data[length:])
        return payload

    @ohneio.protocol
    def read(self):
        return (yield from self.read_some())


@ohneio.protocol
def SSReader(cipher):
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
def AddrReader():
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
