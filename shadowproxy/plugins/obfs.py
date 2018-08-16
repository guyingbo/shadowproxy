from datetime import datetime
from .. import gvars

request_tmpl = (
    b"GET / HTTP/1.1\r\n"
    b"Host: {}\r\n"
    b"User-Agent: Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)\r\n"
    b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    b"Accept-Language: en-US,en;q=0.8\r\n"
    b"Accept-Encoding: gzip, deflate\r\n"
    b"DNT: 1\r\n"
    b"Connection: keep-alive\r\n\r\n"
)


class HttpSimplePlugin:
    name = "http_simple"

    async def init_server(self, client):
        buf = bytearray()
        start = 0
        while True:
            data = await client.recv(gvars.PACKET_SIZE)
            if not data:
                return
            buf.extend(data)
            index = buf.find(b"\r\n\r\n", start)
            if index == -1:
                start = len(buf) - 3
                start = start if start > 0 else 0
                continue
            head = bytes.fromhex(
                buf.split(b" ", 2)[1][1:].replace(b"%", b"").decode("ascii")
            )
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
            redundant = head + memoryview(buf)[index + 4 :].tobytes()
            recv = client.recv

            async def disposable_recv(size):
                client.recv = recv
                return redundant

            client.recv = disposable_recv
            return
