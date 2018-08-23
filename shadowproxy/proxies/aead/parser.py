import iofree


class AEADProtocol:
    def __init__(self, cipher):
        self.cipher = cipher

    def parser(self, *args, **kwargs):
        return iofree.Parser(self.reader(*args, **kwargs))

    def reader(self):
        salt = yield from iofree.read(self.cipher.SALT_SIZE)
        self.decrypt = self.cipher.make_decrypter(salt)
        while True:
            payload = yield from self.read_some()
            yield from iofree.write(payload)

    def read_some(self):
        chunk0 = yield from iofree.read(2 + self.cipher.TAG_SIZE)
        data = memoryview(chunk0)
        length_bytes = self.decrypt(data[:2], data[2:])
        length = int.from_bytes(length_bytes, "big")
        if length != length & 0x3FFF:
            raise Exception("invalid length")
        chunk1 = yield from iofree.read(length + self.cipher.TAG_SIZE)
        data = memoryview(chunk1)
        payload = self.decrypt(data[:length], data[length:])
        return payload
