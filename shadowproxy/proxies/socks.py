from .. import gvars
from ..utils import pack_addr
from .base import ProxyBase
from ..protocols.socks import Socks5Reader


class SocksProxy(ProxyBase):
    proto = "SOCKS"

    def __init__(self, auth=None, via=None, plugin=None):
        self.auth = auth
        self.via = via
        self.plugin = plugin

    async def _run(self):
        socks5 = Socks5Reader(self.auth)

        via_client = None
        while True:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                break
            socks5.send(data)
            data = socks5.read()
            if data:
                await self.client.sendall(data)
            if not socks5.has_result:
                continue
            self.target_addr, cmd = socks5.get_result()
            print(self, cmd)
            if cmd == 1:  # connect
                via_client = await self.connect_server(self.target_addr)
                redundant = socks5.input.read()
                if redundant:
                    print("redundant:", redundant)
                    await self.client.sendall(redundant)
                await self.client.sendall(self._make_resp())
            break

        if via_client:
            async with via_client:
                await self.relay(via_client)

    def _make_resp(self, code=0, host="0.0.0.0", port=0):
        return b"\x05" + code.to_bytes(1, "big") + b"\x00" + pack_addr((host, port))
