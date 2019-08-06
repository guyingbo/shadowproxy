import base64
from urllib import parse
from ... import gvars
from ..base.server import ProxyBase
from .parser import http_request
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
        parser = http_request.parser()
        while not parser.has_result:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                raise Exception("incomplete http connect request")
            parser.send(data)
        if self.auth:
            pauth = parser.headers.get(b"Proxy-Authorization", None)
            httpauth = b"Basic " + base64.b64encode(b":".join(self.auth))
            if httpauth != pauth:
                await self.client.sendall(
                    parser.ver + b" 407 Proxy Authentication Required\r\n"
                    b"Connection: close\r\n"
                    b'Proxy-Authenticate: Basic realm="simple"\r\n\r\n'
                )
                raise Exception("Unauthorized HTTP Request")
        if parser.method == b"CONNECT":
            self.proto = "HTTP(CONNECT)"
            host, _, port = parser.path.partition(b":")
            self.target_addr = (host.decode(), int(port))
        else:
            self.proto = "HTTP(PASS)"
            url = parse.urlparse(parser.path)
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
            if parser.method == b"CONNECT":
                await self.client.sendall(
                    b"HTTP/1.1 200 Connection: Established\r\n\r\n"
                )
                remote_req_headers = b""
            else:
                headers_list = [
                    b"%s: %s" % (k, v)
                    for k, v in parser.headers.items()
                    if not k.startswith(b"Proxy-")
                ]
                if isinstance(via_client, HTTPForwardClient):
                    headers_list.extend(via_client.extra_headers)
                    newpath = url.geturl()
                lines = b"\r\n".join(headers_list)
                remote_req_headers = b"%s %s %s\r\n%s\r\n\r\n" % (
                    parser.method,
                    newpath,
                    parser.ver,
                    lines,
                )
            redundant = parser.readall()
            to_send = remote_req_headers + redundant
            if to_send:
                await via_client.sendall(to_send)
            await self.relay(via_client)
