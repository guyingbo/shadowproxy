from ... import gvars
from ..base.server import ProxyBase
from .parser import addr_reader, ss_reader


class SSProxy(ProxyBase):
    proto = "SS"

    def __init__(self, cipher, via=None, plugin=None):
        self.cipher = cipher
        self.via = via
        self.plugin = plugin
        self.ss_parser = ss_reader.parser(self.cipher)

    async def _run(self):
        addr_parser = addr_reader.parser()

        if hasattr(self.plugin, "make_recv_func"):
            self._recv = self.plugin.make_recv_func(self.client)
        else:
            self._recv = self.client.recv

        while True:
            data = await self._recv(gvars.PACKET_SIZE)
            if not data:
                break
            self.ss_parser.send(data)
            data = self.ss_parser.read()
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
        self.ss_parser.send(data)
        return self.ss_parser.read()

    async def sendall(self, data):
        iv = b""
        if not hasattr(self, "encrypt"):
            iv, self.encrypt = self.cipher.make_encrypter()
        to_send = iv + self.encrypt(data)
        if hasattr(self.plugin, "encode"):
            to_send = self.plugin.encode(to_send)
        await self.client.sendall(to_send)
