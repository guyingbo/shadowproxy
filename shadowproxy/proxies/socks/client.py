from ... import gvars
from ..base.client import ClientBase
from ...utils import pack_addr
from .parser import Socks5ResponseParser


class SocksClient(ClientBase):
    name = "socks"

    async def init(self):
        response_parser = Socks5ResponseParser()
        if self.ns.auth:
            methods = b"\x00\x02"
        else:
            methods = b"\x00"

        handshake = b"\x05" + len(methods).to_bytes(1, "big") + methods
        request = b"\x05\x01\x00" + pack_addr(self.target_addr)
        await self.sock.sendall(handshake + request)
        while True:
            data = await self.sock.recv(gvars.PACKET_SIZE)
            if not data:
                break
            response_parser.send(data)
            if response_parser.has_result:
                break
        redundant = response_parser.input.read()
        if redundant:
            recv = self.sock.recv

            async def disposable_recv(size):
                self.sock.recv = recv
                return redundant

            self.sock.recv = disposable_recv
