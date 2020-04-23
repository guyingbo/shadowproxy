import abc
from time import time
from urllib import parse

from ... import gvars
from ...utils import open_connection


class HTTPResponse:
    def __init__(self, client):
        self.client = client
        self.done = False
        self.header_size = 0
        self.body_size = 0
        self.speed = 0
        self.start = time()

    @property
    def size(self):
        return self.header_size + self.body_size

    def on_header(self, name: bytes, value: bytes):
        self.header_size += len(name) + len(value)

    def on_message_complete(self):
        self.done = True
        seconds = time() - self.start
        self.speed = int(self.size / 1024 / seconds)  # KB/s

    def on_body(self, body: bytes):
        self.body_size += len(body)


class ClientBase(abc.ABC):
    sock = None
    target_addr = ("unknown", -1)

    def __init__(self, namespace):
        self.ns = namespace

    def __repr__(self):
        return f"{self.__class__.__name__}({self})"

    def __str__(self):
        return f"{self.bind_address} -- {self.target_address}"

    async def __aenter__(self):
        return self

    async def __aexit__(self, et, e, tb):
        await self.close()

    async def close(self):
        if self.sock:
            await self.sock.close()
            self.sock = None

    @property
    @abc.abstractmethod
    def proto(self):
        ""

    @property
    def bind_address(self) -> str:
        return f"{self.ns.bind_addr[0]}:{self.ns.bind_addr[1]}"

    @property
    def target_address(self) -> str:
        return f"{self.target_addr[0]}:{self.target_addr[1]}"

    async def connect(self, target_addr, source_addr=None):
        self.target_addr = target_addr
        if self.sock:
            return
        self.sock = await open_connection(*self.ns.bind_addr, source_addr=source_addr)

    @abc.abstractmethod
    async def init(self):
        ""

    async def recv(self, size):
        return await self.sock.recv(size)

    async def sendall(self, data):
        return await self.sock.sendall(data)

    async def http_request(
        self, uri: str, method: str = "GET", headers: list = None, response_cls=None
    ):
        import httptools

        response_cls = response_cls or HTTPResponse
        url = parse.urlparse(uri)
        host, _, port = url.netloc.partition(":")
        try:
            port = int(port)
        except ValueError:
            if url.scheme == "http":
                port = 80
            elif url.scheme == "https":
                port = 443
            else:
                raise Exception(f"unknown scheme: {url.scheme}")
        target_addr = (host, port)
        await self.connect(target_addr)
        await self.init()

        header_list = [f"Host: {self.target_address}".encode()]
        if headers:
            for header in headers:
                if isinstance(header, str):
                    header = header.encode()
                header_list.append(header)
        ver = b"HTTP/1.1"
        method = method.upper().encode()
        url = url.geturl().encode()
        data = b"%b %b %b\r\n%b\r\n\r\n" % (method, url, ver, b"\r\n".join(header_list))
        await self.sendall(data)
        response = response_cls(self)
        parser = httptools.HttpResponseParser(response)
        while not response.done:
            data = await self.recv(gvars.PACKET_SIZE)
            if not data:
                raise Exception("Incomplete response")
            parser.feed_data(data)
        return response
