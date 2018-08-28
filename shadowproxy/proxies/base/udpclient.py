import curio
import weakref
from curio import socket
from ... import gvars

IP_TRANSPARENT = 19


class UDPClient:
    def __init__(self, ns=None):
        self.ns = ns
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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


def Sendto():
    bind_socks = weakref.WeakValueDictionary()

    async def sendto_from(bind_addr, data, addr):
        if bind_addr not in bind_socks:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sender.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            sender.bind(bind_addr)
            bind_socks[bind_addr] = sender
        sender = bind_socks[bind_addr]
        async with sender:
            await sender.sendto(data, addr)

    return sendto_from


sendto_from = Sendto()
