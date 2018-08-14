import curio
import weakref
from .. import gvars
from curio import socket
from ..utils import pack_addr, unpack_addr

IP_TRANSPARENT = 19


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
            gvars.logger.debug(f"{bind_addr} {e}")

    return sendto_from


sendto_from = Sendto()


class SSUDPServer:
    proto = "SS(UDP)"

    def __init__(self, cipher):
        self.via = UDPClient
        self.cipher = cipher
        self.removed = None

        def callback(key, value):
            self.removed = (key, value)

        import pylru

        self.addr2client = pylru.lrucache(256, callback)

    async def __call__(self, sock):
        listen_addr = sock.getsockname()
        async with curio.TaskGroup as g:
            while True:
                data, addr = await sock.recvfrom(8192)
                if len(data) <= self.cipher.IV_SIZE:
                    continue
                if addr not in self.addr2client:
                    via_client = self.via()
                    self.addr2client[addr] = via_client
                    if self.removed is not None:
                        await self.removed[1].close()
                        self.removed = None
                via_client = self.addr2client[addr]
                iv = data[: self.cipher.IV_SIZE]
                decrypt = self.cipher.make_decrypter(iv)
                data = decrypt(data[self.cipher.IV_SIZE :])
                target_addr, payload = unpack_addr(data)
                gvars.logger.debug(
                    f"udp: {addr[0]}:{addr[1]} -> "
                    f"{listen_addr[0]}:{listen_addr[1]} -> "
                    f"{target_addr[0]}:{target_addr[1]}"
                )
                await via_client.sendto(payload, target_addr)

                async def sendto(data, target_addr):
                    iv, encrypt = self.cipher.make_encrypter()
                    payload = encrypt(pack_addr(target_addr) + data)
                    await sock.sendto(iv + payload, addr)

                await via_client.relay(g, addr, listen_addr, sendto)


class UDPClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._relay_task = None

    async def sendto(self, data, addr):
        await self.sock.sendto(data, addr)

    async def relay(self, g, addr, listen_addr, sendfunc=None):
        if self._relay_task is None:
            self._relay_task = await g.spawn(self._relay(addr, listen_addr, sendfunc))

    async def _relay(self, addr, listen_addr, sendfunc):
        while True:
            data, raddr = await self.sock.recvfrom(gvars.PACKET_SIZE)
            gvars.logger.debug(
                f"udp: {addr[0]}:{addr[1]} <- "
                f"{listen_addr[0]}:{listen_addr[1]} <- "
                f"{raddr[0]}:{raddr[1]}"
            )
            if sendfunc is None:
                await sendto_from(raddr, data, addr)
            else:
                await sendfunc(data, raddr)

    async def close(self):
        await self._relay_task.cancel()
        await self.sock.close()


class SSUDPClient(UDPClient):
    def __init__(self, cipher, host, port):
        self.cipher = cipher
        self.raddr = (host, port)
        super().__init__()

    async def sendto(self, data, addr):
        self.taddr = addr
        iv, encrypt = self.cipher.make_encrypter()
        payload = iv + encrypt(pack_addr(addr) + data)
        await self.sock.sendto(payload, self.raddr)

    def _unpack(self, data):
        iv = data[: self.cipher.IV_SIZE]
        decrypt = self.cipher.make_decrypter(iv)
        data = decrypt(data[self.cipher.IV_SIZE :])
        addr, payload = unpack_addr(data)
        return payload, addr

    async def _relay(self, addr, listen_addr, sendfunc):
        while True:
            data, _ = await self.sock.recvfrom(gvars.PACKET_SIZE)
            payload, taddr = self._unpack(data)
            gvars.logger.debug(
                f"udp: {addr[0]}:{addr[1]} <- "
                f"{listen_addr[0]}:{listen_addr[1]} <- "
                f"{self.raddr[0]}:{self.raddr[1]} <- "
                f"{self.taddr[0]}:{self.taddr[1]}"
            )
            if sendfunc is None:
                await sendto_from(self.taddr, payload, addr)
            else:
                await sendfunc(payload, addr)
