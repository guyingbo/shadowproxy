import re
import base64
from urllib import parse
from .. import gvars, __version__
from ..utils import open_connection
from .base import ProxyBase, ClientBase

HTTP_LINE = re.compile(b"([^ ]+) +(.+?) +(HTTP/[^ ]+)")


class HTTPProxy(ProxyBase):
    proto = "HTTP"

    def __init__(self, auth=None, via=None):
        self.auth = auth
        self.via = via

    async def _run(self):
        buf = bytearray()
        start = 0
        while True:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                return
            buf.extend(data)
            index = buf.find(b"\r\n\r\n", start)
            if index == -1:
                start = len(buf) - 3
                start = start if start > 0 else 0
                continue
            break
        buf_mem = memoryview(buf)
        header_lines = buf_mem[:index].tobytes()
        redundant = buf_mem[index + 4 :].tobytes()
        headers = header_lines.split(b"\r\n")
        method, path, ver = HTTP_LINE.fullmatch(headers.pop(0)).groups()
        lines = b"\r\n".join(line for line in headers if not line.startswith(b"Proxy-"))
        headers = dict(line.split(b": ", 1) for line in headers)
        if self.auth:
            pauth = headers.get(b"Proxy-Authenticate", None)
            httpauth = b"Basic " + base64.b64encode(b":".join(self.auth))
            if httpauth != pauth:
                await self.client.sendall(
                    ver + b" 407 Proxy Authentication Required\r\n"
                    b"Connection: close\r\n"
                    b'Proxy-Authenticate: Basic realm="simple"\r\n\r\n'
                )
                raise Exception("Unauthorized HTTP Request")
        if method == b"CONNECT":
            self.proto = "HTTPS"
            host, _, port = path.partition(b":")
            self.target_addr = (host.decode(), int(port))
        else:
            url = parse.urlparse(path)
            if not url.hostname:
                await self.client.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Connection: close\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: 2\r\n\r\n"
                    b"ok"
                )
                return
            self.target_addr = (url.hostname.decode(), url.port or 80)
            newpath = url._replace(netloc=b"", scheme=b"").geturl()
        via_client = await self.connect_server(self.target_addr)
        gvars.logger.info(self)
        async with via_client:
            if method == b"CONNECT":
                await self.client.sendall(
                    b"HTTP/1.1 200 Connection: Established\r\n\r\n"
                )
                remote_req_headers = b""
            else:
                remote_req_headers = b"%s %s %s\r\n%s\r\n\r\n" % (
                    method,
                    newpath,
                    ver,
                    lines,
                )
            to_send = remote_req_headers + redundant
            if to_send:
                await via_client.sendall(to_send)
            await self.relay(via_client)


class HTTPClient(ClientBase):
    redundant = None
    async def connect(self, target_addr):
        self.target_addr = target_addr
        self.sock = await open_connection(*self.ns.bind_addr)
        if target_addr[1] != 443:
            await self.init_https()
        else:
            await self.init_https()

    async def init_http(self):
        pass

    async def init_https(self):
        headers_str = (
            f"CONNECT {self.target_address} HTTP/1.1\r\n"
            f"Host: {self.target_address}\r\n"
            f"User-Agent: shadowproxy/{__version__}\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
        )
        auth = getattr(self.ns, "auth", None)
        if auth:
            headers_str += "Proxy-Authorization: Basic {}\r\n".format(
                base64.b64encode(b":".join(auth)).decode()
            )
        headers_str += "\r\n"
        await self.sock.sendall(headers_str.encode())
        buf = bytearray()
        start = 0
        while True:
            data = await self.sock.recv(gvars.PACKET_SIZE)
            if not data:
                return
            buf.extend(data)
            index = buf.find(b"\r\n\r\n", start)
            if index == -1:
                start = len(buf) - 3
                start = start if start > 0 else 0
                continue
            break
        buf_mem = memoryview(buf)
        header_lines = buf_mem[:index].tobytes()
        self.redundant = buf_mem[index + 4 :].tobytes()
        if not header_lines.startswith(b"HTTP/1.1 200"):
            gvars.logger.debug(f"{self} got {data}")
            raise Exception(data)

    async def sendall(self, data):
        return await self.sock.sendall(data)

    async def recv(self, size):
        if self.redundant:
            redundant = self.redundant
            self.redundant = b""
            return redundant
        return await self.sock.recv(size)
