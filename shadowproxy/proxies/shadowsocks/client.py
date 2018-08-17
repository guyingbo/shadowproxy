from ...utils import pack_addr
from ..base.client import ClientBase
from ...protocols.shadowsocks import SSReader


class SSClient(ClientBase):
    def _init(self):
        self.ss_reader = SSReader(self.ns.cipher)

    async def init(self):
        iv, self.encrypt = self.ns.cipher.make_encrypter()
        data = iv + self.encrypt(pack_addr(self.target_addr))
        await self.sock.sendall(data)

    async def recv(self, size):
        data = await self.sock.recv(size)
        if not data:
            return data
        self.ss_reader.send(data)
        data = self.ss_reader.read()
        if not data:
            data = await self.recv(size)
        return data

    async def sendall(self, data):
        data = self.encrypt(data)
        await self.sock.sendall(data)
