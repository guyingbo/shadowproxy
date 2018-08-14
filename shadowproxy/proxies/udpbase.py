import weakref
from curio import socket


def Sendto():
    socks = weakref.WeakValueDictionary()

    async def sendto_from(bind_addr, data, addr):
        try:
            if bind_addr not in socks:
                sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sender.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                sender.bind(bind_addr)
                socks[bind_addr] = sender
            sender = socks[bind_addr]
            async with sender:
                await sender.sendto(data, addr)
        except OSError as e:
            if verbose > 0:
                print(e, bind_addr)

    return sendto_from


sendto_from = Sendto()


class UDPClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._relay_task = None

    async def sendto(self, data, addr):
        await self.sock.sendto(data, addr)

    async def relay(self, addr, listen_addr, sendfunc=None):
        if self._relay_task is None:
            self._relay_task = await spawn(self._relay(addr, listen_addr, sendfunc))

    async def _relay(self, addr, listen_addr, sendfunc):
        try:
            while True:
                data, raddr = await self.sock.recvfrom(8192)
                if verbose > 0:
                    print(
                        f"udp: {addr[0]}:{addr[1]} <-- "
                        f"{listen_addr[0]}:{listen_addr[1]} <-- "
                        f"{raddr[0]}:{raddr[1]}"
                    )
                if sendfunc is None:
                    await sendto_from(raddr, data, addr)
                else:
                    await sendfunc(data, raddr)
        except CancelledError:
            pass

    async def close(self):
        await self._relay_task.cancel()
        await self.sock.close()
