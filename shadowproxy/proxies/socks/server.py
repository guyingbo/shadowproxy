from ... import gvars
from ...utils import pack_addr
from ..base.server import ProxyBase
from .parser import socks5_request, socks4_request


class SocksProxy(ProxyBase):
    proto = "SOCKS"

    def __init__(self, bind_addr, auth=None, via=None, plugin=None, **kwargs):
        self.bind_addr = bind_addr
        self.auth = auth
        self.via = via
        self.plugin = plugin
        self.kwargs = kwargs

    async def _run(self):
        socks5_parser = socks5_request.parser(self.auth)

        while not socks5_parser.has_result:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                return
            socks5_parser.send(data)
            data = socks5_parser.read()
            if data:
                await self.client.sendall(data)
        self.target_addr, cmd = socks5_parser.get_result()
        assert cmd == 1, f"only support connect command {cmd}"
        via_client = await self.connect_server(self.target_addr)
        await self.client.sendall(self._make_resp())

        async with via_client:
            redundant = socks5_parser.readall()
            if redundant:
                await via_client.sendall(redundant)
            await self.relay(via_client)

    def _make_resp(self, code=0, host="0.0.0.0", port=0):
        return b"\x05" + code.to_bytes(1, "big") + b"\x00" + pack_addr((host, port))


class Socks4Proxy(ProxyBase):
    proto = "SOCKS4"

    def __init__(self, bind_addr, auth=None, via=None, plugin=None, **kwargs):
        self.bind_addr = bind_addr
        self.auth = auth
        self.via = via
        self.plugin = plugin
        self.kwargs = kwargs

    async def _run(self):
        socks4_parser = socks4_request.parser()

        while not socks4_parser.has_result:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                return
            socks4_parser.send(data)
            data = socks4_parser.read()
        self.target_addr = socks4_parser.get_result()
        via_client = await self.connect_server(self.target_addr)
        await self.client.sendall(b"\x00\x5a\x00\x00\x00\x00\x00\x00")

        async with via_client:
            redundant = socks4_parser.readall()
            if redundant:
                await via_client.sendall(redundant)
            await self.relay(via_client)
