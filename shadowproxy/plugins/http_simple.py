from datetime import datetime
from .. import gvars
from .base import Plugin
from ..utils import set_disposable_recv
from ..proxies.http.parser import http_response, http_request

request_tmpl = (
    b"GET / HTTP/1.1\r\n"
    b"Host: %s\r\n"
    b"User-Agent: Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)\r\n"
    b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    b"Accept-Language: en-US,en;q=0.8\r\n"
    b"Accept-Encoding: gzip, deflate\r\n"
    b"DNT: 1\r\n"
    b"Connection: keep-alive\r\n\r\n"
)


class HttpSimplePlugin(Plugin):
    name = "http_simple"

    async def init_server(self, client):
        parser = http_request.parser()
        while not parser.has_result:
            data = await client.recv(gvars.PACKET_SIZE)
            if not data:
                raise Exception("incomplete http request")
            parser.send(data)
        head = bytes.fromhex(parser.path[1:].replace(b"%", b"").decode("ascii"))
        await client.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Connection: keep-alive\r\n"
            b"Content-Encoding: gzip\r\n"
            b"Content-Type: text/html\r\n"
            b"Date: "
            + datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT").encode()
            + b"\r\nServer: nginx\r\n"
            b"Vary: Accept-Encoding\r\n\r\n"
        )
        redundant = head + parser.readall()
        set_disposable_recv(client, redundant)

    async def init_client(self, client):
        request = request_tmpl % client.target_address.encode()
        await client.sock.sendall(request)
        parser = http_response.parser()
        while not parser.has_result:
            data = await client.sock.recv(gvars.PACKET_SIZE)
            if not data:
                raise Exception("http_simple plugin handshake failed")
            parser.send(data)
        assert (
            parser.code == b"200"
        ), f"bad status code {parser.code} {parser.status}"
        redundant = parser.readall()
        set_disposable_recv(client.sock, redundant)
