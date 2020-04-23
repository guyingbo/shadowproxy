import struct

from curio import socket

from ... import gvars
from ..base.server import ProxyBase

SO_ORIGINAL_DST = 80


class TransparentProxy(ProxyBase):
    proto = "REDIRECT"

    def __init__(self, bind_addr, via=None, plugin=None, **kwargs):
        self.bind_addr = bind_addr
        self.via = via
        self.plugin = plugin
        self.kwargs = kwargs

    async def _run(self):
        try:
            buf = self.client._socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port, host = struct.unpack("!2xH4s8x", buf)
            self.target_addr = (socket.inet_ntoa(host), port)
        except Exception:
            gvars.logger.exception(f"{self} isn't a redirect proxy")

        via_client = await self.connect_server(self.target_addr)
        async with via_client:
            await self.relay(via_client)
