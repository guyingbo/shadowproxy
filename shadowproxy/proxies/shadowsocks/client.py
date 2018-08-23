from ...utils import pack_addr
from ..base.client import ClientBase
from .parser import ss_reader


class SSClient(ClientBase):
    def _init(self):
        self.ss_parser = ss_reader.parser(self.ns.cipher)

    async def init(self):
        plugin = getattr(self.ns, "plugin", None)
        if plugin:
            await plugin.init_client(self)
        iv, self.encrypt = self.ns.cipher.make_encrypter()
        data = iv + self.encrypt(pack_addr(self.target_addr))
        await self.sock.sendall(data)

    async def recv(self, size):
        data = await self.sock.recv(size)
        if not data:
            return data
        self.ss_parser.send(data)
        data = self.ss_parser.read()
        if not data:
            data = await self.recv(size)
        return data

    async def sendall(self, data):
        data = self.encrypt(data)
        await self.sock.sendall(data)
