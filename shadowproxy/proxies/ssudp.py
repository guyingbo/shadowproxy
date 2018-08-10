from ..utils import pack_addr, unpack_addr


class SSUDPServer:
    proto = "SS(UDP)"

    def __init__(self, cipher):
        self.via = UDPClient
        self.cipher = cipher
        self.removed = None

        def callback(key, value):
            self.removed = (key, value)

        import pylru

        self.addr2client = pylru.lrucache(256, callback)

    async def __call__(self, sock):
        listen_addr = sock.getsockname()
        while True:
            data, addr = await sock.recvfrom(8192)
            if len(data) <= self.cipher.IV_SIZE:
                continue
            if addr not in self.addr2client:
                via_client = self.via()
                self.addr2client[addr] = via_client
                if self.removed is not None:
                    await self.removed[1].close()
                    self.removed = None
            via_client = self.addr2client[addr]
            iv = data[: self.cipher.IV_SIZE]
            decrypt = self.cipher.make_decrypter(iv)
            data = decrypt(data[self.cipher.IV_SIZE :])
            taddr, payload = unpack_addr(data)
            if verbose > 0:
                print(
                    f"udp: {addr[0]}:{addr[1]} --> "
                    f"{listen_addr[0]}:{listen_addr[1]} --> "
                    f"{taddr[0]}:{taddr[1]}"
                )
            await via_client.sendto(payload, taddr)

            async def sendto(data, taddr):
                iv, encrypt = self.cipher.make_encrypter()
                payload = encrypt(pack_addr(taddr) + data)
                await sock.sendto(iv + payload, addr)

            await via_client.relay(addr, listen_addr, sendto)
