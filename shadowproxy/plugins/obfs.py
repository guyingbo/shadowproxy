from datetime import datetime
from .. import gvars


class HttpSimplePlugin:
    def __init__(self):
        pass

    async def run(self, client):
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
                client.rev = recv
                return redundant

            client.recv = disposable_recv
            return
