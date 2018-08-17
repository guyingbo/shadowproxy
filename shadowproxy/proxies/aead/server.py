from ... import gvars
from ..base.server import ProxyBase
from ...protocols.shadowsocks import AEADReader, AddrReader


class AEADProxy(ProxyBase):
    proto = "AEAD"

    def __init__(self, cipher, via=None):
        self.cipher = cipher
        self.via = via
        self.data_reader = AEADReader(self.cipher).read()

    async def recv(self, size):
        while True:
            data = await self.client.recv(size)
            self.data_reader.send(data)
            data = self.data_reader.read()
            if data:
                return data

    async def sendall(self, data):
        packet = b""
        if not hasattr(self, "encrypt"):
            packet, self.encrypt = self.cipher.make_encrypter()
        length = len(data)
        packet += b"".join(self.encrypt(length.to_bytes(2, "big")))
        packet += b"".join(self.encrypt(data))
        await self.client.sendall(packet)

    async def _run(self):
        aead_reader = AEADReader(self.cipher).new()
        addr_reader = AddrReader()

        via_client = None
        while True:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                break
            aead_reader.send(data)
            data = aead_reader.read()
            if not data:
                continue
            addr_reader.send(data)
            if not addr_reader.has_result:
                continue
            self.target_addr, _ = addr_reader.get_result()
            print(self.target_addr, _)
            via_client = await self.connect_server(self.target_addr)

        if via_client:
            async with via_client:
                if redundant:
                    await via_client.sendall(redundant)
                await self.relay(via_client)
