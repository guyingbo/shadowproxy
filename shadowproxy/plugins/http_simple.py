from datetime import datetime

from ..protocols import http
from ..utils import run_parser_curio, set_disposable_recv
from .base import Plugin

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
        parser = http.HTTPRequest.get_parser()
        request = await run_parser_curio(parser, client)
        head = bytes.fromhex(request.path[1:].replace(b"%", b"").decode("ascii"))
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
        parser = http.HTTPResponse.get_parser()
        response = await run_parser_curio(parser, client.sock)
        assert (
            response.code == b"200"
        ), f"bad status code {response.code} {response.status}"
        redundant = parser.readall()
        set_disposable_recv(client.sock, redundant)
