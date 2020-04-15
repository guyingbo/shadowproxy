import iofree


@iofree.parser
def ss_reader(cipher):
    parser = yield from iofree.get_parser()
    iv = yield from iofree.read(cipher.IV_SIZE)
    decrypt = cipher.make_decrypter(iv)
    while True:
        data = yield from iofree.read_more()
        parser.respond(result=decrypt(data))
