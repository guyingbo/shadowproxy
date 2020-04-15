import iofree


@iofree.parser
def aead_reader(cipher):
    parser = yield from iofree.get_parser()
    parser.cipher = cipher
    salt = yield from iofree.read(cipher.SALT_SIZE)
    parser.decrypt = cipher.make_decrypter(salt)
    while True:
        payload = yield from _read_some()
        parser.respond(result=payload)


def _read_some():
    parser = yield from iofree.get_parser()
    chunk0 = yield from iofree.read(2 + parser.cipher.TAG_SIZE)
    with memoryview(chunk0) as data:
        length_bytes = parser.decrypt(data[:2], data[2:])
    length = int.from_bytes(length_bytes, "big")
    if length != length & 0x3FFF:  # 16 * 1024 - 1
        raise Exception("length exceed limit")
    chunk1 = yield from iofree.read(length + parser.cipher.TAG_SIZE)
    with memoryview(chunk1) as data:
        payload = parser.decrypt(data[:length], data[length:])
    return payload
