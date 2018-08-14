from .. import gvars
from ..utils import pack_addr, open_connection
from .base import ProxyBase, ClientBase
from ..protocols.shadowsocks import AddrReader, SSReader


class SSProxy(ProxyBase):
    proto = "SS"

    def __init__(self, cipher, via=None, plugin=None):
        self.cipher = cipher
        self.via = via
        self.plugin = plugin
        self.ss_reader = SSReader(self.cipher)

    async def _run(self):
        addr_reader = AddrReader()

        via_client = None
        while True:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                break
            self.ss_reader.send(data)
            data = self.ss_reader.read()
            addr_reader.send(data)
            if not addr_reader.has_result:
                continue
            self.target_addr, _ = addr_reader.get_result()
            via_client = await self.connect_server(self.target_addr)
            gvars.logger.info(self)
            break

        if via_client:
            async with via_client:
                redundant = addr_reader.input.read()
                if redundant:
                    await via_client.sendall(redundant)
                await self.relay(via_client)

    async def recv(self, size):
        data = await self.client.recv(size)
        if not data:
            return data
        self.ss_reader.send(data)
        return self.ss_reader.read()

    async def sendall(self, data):
        if not hasattr(self, "encrypt"):
            iv, self.encrypt = self.cipher.make_encrypter()
            await self.client.sendall(iv)
        await self.client.sendall(self.encrypt(data))


class SSClient(ClientBase):
    def _init(self):
        self.ss_reader = SSReader(self.ns.cipher)

    async def connect(self, target_addr):
        self.target_addr = target_addr
        self.sock = await open_connection(*self.ns.bind_addr)
        iv, self.encrypt = self.ns.cipher.make_encrypter()
        data = iv + self.encrypt(pack_addr(target_addr))
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
