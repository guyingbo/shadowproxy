import random
from curio import socket
from ... import gvars
from ..base.client import ClientBase
from ...utils import pack_addr
from .parser import Socks5ResponseParser, Socks4ResponseParser


def pack_ipv4(addr, userid: bytes = b"\x01\x01") -> bytes:
    host, port = addr
    tail = b""
    try:
        packed = socket.inet_aton(host)
    except OSError:
        packed = b"\x00\x00\x00\x01"
        tail = host.encode() + b"\x00"
    return port.to_bytes(2, "big") + packed + userid + b"\x00" + tail


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


class Socks4Client(ClientBase):
    async def init(self):
        response_parser = Socks4ResponseParser()
        info = await socket.getaddrinfo(
            *self.target_addr,
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP
        )
        addr = random.choice(info)[-1]
        handshake = b"\x04\x01" + pack_ipv4(addr)
        await self.sock.sendall(handshake)
        while True:
            data = await self.sock.recv(gvars.PACKET_SIZE)
            if not data:
                raise Exception("socks4 handshake failed")
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
