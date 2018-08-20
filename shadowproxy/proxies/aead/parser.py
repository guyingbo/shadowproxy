import ohneio
import struct


class AEADParser:
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
