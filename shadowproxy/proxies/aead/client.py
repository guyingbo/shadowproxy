from ...utils import pack_addr
from ..base.client import ClientBase
from .parser import aead_reader


class AEADClient(ClientBase):
    proto = "AEAD"

    async def init(self):
        self.aead_parser = aead_reader.parser(self.ns.cipher)
        self.plugin = getattr(self.ns, "plugin", None)
        if self.plugin:
            self.plugin.client = self
            await self.plugin.init_client(self)
        salt, self.encrypt = self.ns.cipher.make_encrypter()
        data = pack_addr(self.target_addr)
        len_data = len(data).to_bytes(2, "big")
        to_send = salt + b"".join(self.encrypt(len_data)) + b"".join(self.encrypt(data))
        await self.sock.sendall(to_send)

    async def recv(self, size):
        data = await self.sock.recv(size)
        if not data:
            return data
        if self.plugin and hasattr(self.plugin, "decode"):
            data = self.plugin.decode(data)
            if not data:
                return await self.recv(size)
        self.aead_parser.send(data)
        data = self.aead_parser.read_output_bytes()
        if not data:
            data = await self.recv(size)
        return data

    async def sendall(self, data):
        if not data:
            return
        len_data = len(data).to_bytes(2, "big")
        to_send = b"".join(self.encrypt(len_data)) + b"".join(self.encrypt(data))
        await self.sock.sendall(to_send)
