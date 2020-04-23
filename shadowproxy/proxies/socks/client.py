import random

from curio import socket

from ...protocols import socks4, socks5
from ...utils import run_parser_curio, set_disposable_recv
from ..base.client import ClientBase


class SocksClient(ClientBase):
    proto = "SOCKS"

    async def init(self):
        auth = getattr(self.ns, "auth", None)
        client_parser = socks5.client.parser(auth, self.target_addr)
        await run_parser_curio(client_parser, self.sock)
        redundant = client_parser.readall()
        set_disposable_recv(self.sock, redundant)


class Socks4Client(ClientBase):
    proto = "SOCKS4"

    async def init(self):
        info = await socket.getaddrinfo(
            *self.target_addr, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP
        )
        addr = random.choice(info)[-1]
        socks4_client_parser = socks4.client.parser(addr)
        await run_parser_curio(socks4_client_parser, self.sock)
        redundant = socks4_client_parser.readall()
        set_disposable_recv(self.sock, redundant)
