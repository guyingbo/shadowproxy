import base64
from urllib import parse

from ...protocols import http
from ...utils import run_parser_curio
from ..base.server import ProxyBase
from .client import HTTPForwardClient


class HTTPProxy(ProxyBase):
    proto = "HTTP"

    def __init__(self, bind_addr, auth=None, via=None, **kwargs):
        self.bind_addr = bind_addr
        self.auth = auth
        self.via = via
        self.bind_addr = bind_addr
        self.kwargs = kwargs

    async def _run(self):
        parser = http.HTTPRequest.get_parser()
        request = await run_parser_curio(parser, self.client)
        if self.auth:
            pauth = request.headers.get(b"Proxy-Authorization", None)
            httpauth = b"Basic " + base64.b64encode(b":".join(self.auth))
            if httpauth != pauth:
                await self.client.sendall(
                    request.ver + b" 407 Proxy Authentication Required\r\n"
                    b"Connection: close\r\n"
                    b'Proxy-Authenticate: Basic realm="Shadowproxy Auth"\r\n\r\n'
                )
                raise Exception("Unauthorized HTTP Request")
        if request.method == b"CONNECT":
            self.proto = "HTTP(CONNECT)"
            host, _, port = request.path.partition(b":")
            self.target_addr = (host.decode(), int(port))
        else:
            self.proto = "HTTP(PASS)"
            url = parse.urlparse(request.path)
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
        async with via_client:
            if request.method == b"CONNECT":
                await self.client.sendall(
                    b"HTTP/1.1 200 Connection: Established\r\n\r\n"
                )
                remote_req_headers = b""
            else:
                headers_list = [
                    b"%s: %s" % (k, v)
                    for k, v in request.headers.items()
                    if not k.startswith(b"Proxy-")
                ]
                if isinstance(via_client, HTTPForwardClient):
                    headers_list.extend(via_client.extra_headers)
                    newpath = url.geturl()
                lines = b"\r\n".join(headers_list)
                remote_req_headers = b"%s %s %s\r\n%s\r\n\r\n" % (
                    request.method,
                    newpath,
                    request.ver,
                    lines,
                )
            redundant = parser.readall()
            to_send = remote_req_headers + redundant
            if to_send:
                await via_client.sendall(to_send)
            await self.relay(via_client)
