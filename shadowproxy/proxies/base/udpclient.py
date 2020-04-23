import curio
from curio import socket

from ... import gvars


class UDPClient:
    def __init__(self, ns=None):
        self.ns = ns
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if "source_addr" in self.ns:
            self.sock.bind(self.ns["source_addr"])
        self._task = None

    async def sendto(self, data, addr):
        await self.sock.sendto(data, addr)

    async def close(self):
        if self._task:
            self._task.cancel()
        await self.sock.close()

    async def relay(self, addr, sendfrom):
        if self._task is None:
            self._task = await curio.spawn(self._relay, addr, sendfrom)

    async def _relay(self, addr, sendfrom):
        try:
            while True:
                data, raddr = await self.sock.recvfrom(gvars.PACKET_SIZE)
                if raddr != addr:
                    continue
                await sendfrom(data, addr)
        except curio.errors.CancelledError:
            pass
