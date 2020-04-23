import base64

from ... import __version__
from ...protocols import http
from ...utils import run_parser_curio, set_disposable_recv
from ..base.client import ClientBase


class HTTPClient(ClientBase):
    proto = "HTTP(CONNECT)"

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

        parser = http.HTTPResponse.get_parser()
        response = await run_parser_curio(parser, self.sock)

        assert (
            response.code == b"200"
        ), f"bad status code: {parser.code} {parser.status}"
        redundant = parser.readall()
        set_disposable_recv(self.sock, redundant)


class HTTPForwardClient(HTTPClient):
    proto = "HTTP(Forward)"

    async def init(self):
        if self.target_addr[1] == 443:
            await super().init()
        else:
            headers = []
            headers.append(b"Proxy-Connection: Keep-Alive")
            auth = getattr(self.ns, "auth", None)
            if auth:
                headers.append(
                    b"Proxy-Authorization: Basic %s" % base64.b64encode(b":".join(auth))
                )
            self.extra_headers = headers

    async def http_request(
        self, uri: str, method: str = "GET", headers: list = None, response_cls=None
    ):
        headers = headers or []
        headers.append(b"Proxy-Connection: Keep-Alive")
        auth = getattr(self.ns, "auth", None)
        if auth:
            headers.append(
                b"Proxy-Authorization: Basic %s" % base64.b64encode(b":".join(auth))
            )
        return await super().http_request(uri, method, headers, response_cls)
