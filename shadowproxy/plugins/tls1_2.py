import random
from .. import gvars
from .base import Plugin
from .tls_parser import TLS1_2RequestParser, Receiver
from ..utils import set_disposable_recv


def pack_uint16(s):
    return len(s).to_bytes(2, "big") + s


class TLS1_2Plugin(Plugin):
    name = "tls1.2"

    def __init__(self):
        self.tls_version = b"\x03\x03"
        self.hosts = (b"cloudfront.net", b"cloudfront.com")
        self.time_tolerance = 5 * 60

    async def init_server(self, client):
        tls_parser = TLS1_2RequestParser(self)
        hello_sent = False
        while True:
            data = await client.recv(gvars.PACKET_SIZE)
            if not data:
                return
            tls_parser.send(data)
            if not hello_sent:
                server_hello = tls_parser.read()
                if not server_hello:
                    continue
                await client.sendall(server_hello)
                hello_sent = True
            else:
                if not tls_parser.has_result:
                    continue
                break
        redundant = tls_parser.input.read()
        set_disposable_recv(client, redundant)

    def make_recv_func(self, client):
        receiver = Receiver(self)

        async def recv(size):
            while True:
                data = await client.recv(size)
                if not data:
                    return data
                receiver.send(data)
                data = receiver.read()
                if data:
                    return data

        return recv

    def encode(self, data):
        ret = b""
        data = memoryview(data)
        while len(data) > 2048:
            size = min(random.randrange(4096) + 100, len(data))
            ret += b"\x17" + self.tls_version + size.to_bytes(2, "big") + data[:size]
            data = data[size:]
        if len(data) > 0:
            ret += b"\x17" + self.tls_version + pack_uint16(data)
        return ret

    async def init_client(self, client):
        ""
