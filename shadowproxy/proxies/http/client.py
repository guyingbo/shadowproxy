import base64
from ... import gvars, __version__
from ..base.client import ClientBase
from ...utils import set_disposable_recv


class HTTPOnlyClient(ClientBase):
    async def init(self):
        ""

    async def http_request(
        self, uri: str, method: str = "GET", headers: list = None, response_cls=None
    ):
        if uri.startswith("https"):
            uri = "http" + uri[5:]
        headers = headers or []
        headers.append(b"Proxy-Connection: Keep-Alive")
        auth = getattr(self.ns, "auth", None)
        if auth:
            headers.append(
                b"Proxy-Authorization: Basic %s"
                % base64.b64encode(b":".join(auth))
            )
        return await super().http_request(uri, method, headers, response_cls)


class HTTPClient(ClientBase):
    async def init(self):
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
        if not header_lines.startswith(b"HTTP/1.1 200"):
            gvars.logger.debug(f"{self} got {data}")
            raise Exception(data)
        redundant = buf_mem[index + 4 :].tobytes()
        set_disposable_recv(self.sock, redundant)
