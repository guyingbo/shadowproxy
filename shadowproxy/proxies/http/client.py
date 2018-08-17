import base64
from urllib import parse
from ... import gvars, __version__
from ...utils import open_connection
from ..base import ClientBase


class HTTPOnlyClient(ClientBase):
    async def connect(self, target_addr, method, path, headers):
        self.target_addr = target_addr
        self.sock = await open_connection(*self.ns.bind_addr)
        headers = [header.encode() for header in headers]
        headers.append(b"Proxy-Connection: Keep-Alive")
        if self.ns.auth:
            headers.append(
                b"Proxy-Authorization: Basic %s"
                % base64.b64encode(b":".join(self.ns.auth))
            )
        url = parse.urlparse(path.encode())
        newpath = url._replace(
            scheme=b"http", netloc=self.target_address.encode()
        ).geturl()
        ver = b"HTTP/1.1"
        method = method.upper().encode()
        data = b"%b %b %b\r\n%b\r\n\r\n" % (method, newpath, ver, b"\r\n".join(headers))
        await self.sendall(data)

    async def sendall(self, data):
        return await self.sock.sendall(data)

    async def recv(self, size):
        return await self.sock.recv(size)


class HTTPClient(ClientBase):
    redundant = None

    async def connect(self, target_addr):
        self.target_addr = target_addr
        self.sock = await open_connection(*self.ns.bind_addr)
        if target_addr[1] != 443:
            await self.init_https()
        else:
            await self.init_https()

    async def http(self):
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
