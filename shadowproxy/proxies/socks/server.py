from ... import gvars
from ...utils import pack_addr
from ..base.server import ProxyBase
from .parser import Socks5RequestParser


class SocksProxy(ProxyBase):
    proto = "SOCKS"

    def __init__(self, auth=None, via=None, plugin=None):
        self.auth = auth
        self.via = via
        self.plugin = plugin

    async def _run(self):
        socks5_parser = Socks5RequestParser(self.auth)

        via_client = None
        while True:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                break
            socks5_parser.send(data)
            data = socks5_parser.read()
            if data:
                await self.client.sendall(data)
            if not socks5_parser.has_result:
                continue
            self.target_addr, cmd = socks5_parser.get_result()
            if cmd == 1:  # connect
                via_client = await self.connect_server(self.target_addr)
                await self.client.sendall(self._make_resp())
            break

        if via_client:
            async with via_client:
                redundant = socks5_parser.input.read()
                if redundant:
                    await via_client.sendall(redundant)
                await self.relay(via_client)

    def _make_resp(self, code=0, host="0.0.0.0", port=0):
        return b"\x05" + code.to_bytes(1, "big") + b"\x00" + pack_addr((host, port))
