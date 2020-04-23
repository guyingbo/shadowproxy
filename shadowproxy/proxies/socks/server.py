from ...protocols import socks4, socks5
from ...utils import run_parser_curio
from ..base.server import ProxyBase


class SocksProxy(ProxyBase):
    proto = "SOCKS"

    def __init__(self, bind_addr, auth=None, via=None, plugin=None, **kwargs):
        self.bind_addr = bind_addr
        self.auth = auth
        self.via = via
        self.plugin = plugin
        self.kwargs = kwargs

    async def _run(self):
        socks5_parser = socks5.server.parser(self.auth)
        request = await run_parser_curio(socks5_parser, self.client)
        self.target_addr = (request.addr.host, request.addr.port)
        via_client = await self.connect_server(self.target_addr)
        # await self.client.sendall(socks5.resp())
        socks5_parser.send_event(0)
        await run_parser_curio(socks5_parser, self.client)

        async with via_client:
            redundant = socks5_parser.readall()
            if redundant:
                await via_client.sendall(redundant)
            await self.relay(via_client)


class Socks4Proxy(ProxyBase):
    proto = "SOCKS4"

    def __init__(self, bind_addr, auth=None, via=None, plugin=None, **kwargs):
        self.bind_addr = bind_addr
        self.auth = auth
        self.via = via
        self.plugin = plugin
        self.kwargs = kwargs

    async def _run(self):
        socks4_parser = socks4.server.parser()
        self.target_addr = await run_parser_curio(socks4_parser, self.client)
        via_client = await self.connect_server(self.target_addr)
        socks4_parser.send_event(0x5A)
        await run_parser_curio(socks4_parser, self.client)

        async with via_client:
            redundant = socks4_parser.readall()
            if redundant:
                await via_client.sendall(redundant)
            await self.relay(via_client)
