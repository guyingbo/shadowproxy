from ... import gvars
from .parser import AEADProtocol
from ..base.server import ProxyBase
from ..shadowsocks.parser import addr_reader


class AEADProxy(ProxyBase):
    proto = "AEAD"

    def __init__(self, cipher, via=None, plugin=None):
        self.cipher = cipher
        self.via = via
        self.plugin = plugin

    async def _run(self):
        aead_parser = AEADProtocol(self.cipher).parser()
        self.aead_parser = aead_parser
        addr_parser = addr_reader.parser()

        if hasattr(self.plugin, "make_recv_func"):
            self._recv = self.plugin.make_recv_func(self.client)
        else:
            self._recv = self.client.recv

        while True:
            data = await self._recv(gvars.PACKET_SIZE)
            if not data:
                break
            aead_parser.send(data)
            data = aead_parser.read()
            if not data:
                continue
            addr_parser.send(data)
            if addr_parser.has_result:
                break

        self.target_addr, _ = addr_parser.get_result()
        via_client = await self.connect_server(self.target_addr)

        async with via_client:
            redundant = addr_parser.readall()
            if redundant:
                await via_client.sendall(redundant)
            await self.relay(via_client)

    async def recv(self, size):
        data = await self._recv(size)
        if not data:
            return data
        self.aead_parser.send(data)
        data = self.aead_parser.read()
        if data:
            data = await self.recv(size)
        return data

    async def sendall(self, data):
        packet = b""
        if not hasattr(self, "encrypt"):
            packet, self.encrypt = self.cipher.make_encrypter()
        length = len(data)
        packet += b"".join(self.encrypt(length.to_bytes(2, "big")))
        packet += b"".join(self.encrypt(data))
        if hasattr(self.plugin, "encode"):
            packet = self.plugin.encode(packet)
        await self.client.sendall(packet)
