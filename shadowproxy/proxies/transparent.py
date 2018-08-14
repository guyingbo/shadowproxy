import struct
import logging
from .. import gvars
from curio import socket
from .base import ProxyBase

logger = logging.getLogger(__name__)
SO_ORIGINAL_DST = 80


class TransparentProxy(ProxyBase):
    proto = "REDIRECT"

    def __init__(self, via, plugin=None):
        self.via = via
        self.plugin = plugin

    async def _run(self):
        try:
            buf = self.client._socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port, host = struct.unpack("!2xH4s8x", buf)
            self.target_addr = (socket.inet_ntoa(host), port)
        except Exception as e:
            logger.exception(f"{self} isn't a redirect proxy")

        via_client = await self.connect_server(self.target_addr)
        gvars.logger.info(self)
        async with via_client:
            await self.relay(via_client)


class TProxyUDPProxy:
    proto = "RED(UDP)"
