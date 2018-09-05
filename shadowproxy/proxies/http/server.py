import base64
from urllib import parse
from ... import gvars
from ..base.server import ProxyBase
from .parser import http_request


class HTTPProxy(ProxyBase):
    proto = "HTTP"

    def __init__(self, bind_addr, auth=None, via=None):
        self.bind_addr = bind_addr
        self.auth = auth
        self.via = via
        self.bind_addr = bind_addr

    async def _run(self):
        parser = http_request.parser()
        while True:
            data = await self.client.recv(gvars.PACKET_SIZE)
            if not data:
                raise Exception("incomplete http connect request")
            parser.send(data)
            if parser.has_result:
                break
        ns = parser.get_result()
        if self.auth:
            pauth = ns.headers.get(b"Proxy-Authorization", None)
            httpauth = b"Basic " + base64.b64encode(b":".join(self.auth))
            if httpauth != pauth:
                await self.client.sendall(
                    ns.ver + b" 407 Proxy Authentication Required\r\n"
                    b"Connection: close\r\n"
                    b'Proxy-Authenticate: Basic realm="simple"\r\n\r\n'
                )
                raise Exception("Unauthorized HTTP Request")
        if ns.method == b"CONNECT":
            self.proto = "HTTP(CONNECT)"
            host, _, port = ns.path.partition(b":")
            self.target_addr = (host.decode(), int(port))
        else:
            self.proto = "HTTP(ONLY)"
            url = parse.urlparse(ns.path)
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
            if ns.method == b"CONNECT":
                await self.client.sendall(
                    b"HTTP/1.1 200 Connection: Established\r\n\r\n"
                )
                remote_req_headers = b""
            else:
                lines = b"\r\n".join(
                    b"%s: %s" % (k, v)
                    for k, v in ns.headers.items()
                    if not k.startswith(b"Proxy-")
                )
                remote_req_headers = b"%s %s %s\r\n%s\r\n\r\n" % (
                    ns.method,
                    newpath,
                    ns.ver,
                    lines,
                )
            redundant = parser.readall()
            to_send = remote_req_headers + redundant
            if to_send:
                await via_client.sendall(to_send)
            await self.relay(via_client)
