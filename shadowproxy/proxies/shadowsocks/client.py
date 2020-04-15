from ...utils import pack_addr
from ..base.client import ClientBase
from .parser import ss_reader


class SSClient(ClientBase):
    proto = "SS"

    async def init(self):
        self.ss_parser = ss_reader.parser(self.ns.cipher)
        self.plugin = getattr(self.ns, "plugin", None)
        if self.plugin:
            self.plugin.client = self
            await self.plugin.init_client(self)

    async def recv(self, size):
        data = await self.sock.recv(size)
        if not data:
            return data
        if self.plugin and hasattr(self.plugin, "decode"):
            data = self.plugin.decode(data)
            if not data:
                return await self.recv(size)
        self.ss_parser.send(data)
        data = self.ss_parser.read_output_bytes()
        if not data:
            data = await self.recv(size)
        return data

    async def sendall(self, data):
        to_send = b""
        if not hasattr(self, "encrypt"):
            iv, self.encrypt = self.ns.cipher.make_encrypter()
            to_send = iv + self.encrypt(pack_addr(self.target_addr))
        to_send += self.encrypt(data)
        plugin = getattr(self.ns, "plugin", None)
        if plugin and hasattr(plugin, "encode"):
            to_send = plugin.encode(to_send)
        await self.sock.sendall(to_send)
