from datetime import datetime
from .. import gvars


class HttpSimplePlugin:
    def __init__(self):
        pass

    async def run(self, client):
        buf = bytearray()
        while True:
            data = await client.recv(gvars.PACKET_SIZE)
            if not data:
                return
            buf.extend(data)
            index = buf.find(b"\r\n\r\n")
            if index == -1:
                continue
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
            redundant = memoryview(buf)[index + 4 :].tobytes()
            if redundant:
                recv = client.recv

                async def tmp_recv(size):
                    client.rev = recv
                    return redundant

                client.recv = tmp_recv
            return
