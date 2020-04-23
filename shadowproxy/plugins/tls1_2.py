import binascii
import hashlib
import hmac
import os
import random
import struct

from ..utils import run_parser_curio, set_disposable_recv
from .base import Plugin
from .tls_parser import (
    application_data,
    pack_auth_data,
    pack_uint16,
    sni,
    tls1_2_request,
    tls1_2_response,
)


class TLS1_2Plugin(Plugin):
    name = "tls1.2"

    def __init__(self):
        self.tls_version = b"\x03\x03"
        self.hosts = (b"cloudfront.net", b"cloudfront.com")
        self.time_tolerance = 5 * 60

    async def init_server(self, client):
        self.response_parser = application_data.parser(self)
        tls_parser = tls1_2_request.parser(self)
        await run_parser_curio(tls_parser, client)
        redundant = tls_parser.readall()
        set_disposable_recv(client, redundant)

    def decode(self, data):
        self.response_parser.send(data)
        return self.response_parser.read_output_bytes()

    def encode(self, data):
        ret = b""
        with memoryview(data) as data:
            while len(data) > 2048:
                size = min(random.randrange(4096) + 100, len(data))
                ret += (
                    b"\x17" + self.tls_version + size.to_bytes(2, "big") + data[:size]
                )
                data = data[size:]
            if len(data) > 0:
                ret += b"\x17" + self.tls_version + pack_uint16(data)
        return ret

    async def init_client(self, client):
        self.ticket_buf = {}
        self.response_parser = tls1_2_response.parser(self)
        self.session_id = os.urandom(32)
        data = (
            self.tls_version
            + pack_auth_data(client.ns.cipher.master_key, self.session_id)
            + b"\x20"
            + self.session_id
        )
        data += binascii.unhexlify(
            b"001cc02bc02fcca9cca8cc14cc13c00ac014c009c013009c0035002f000a" + b"0100"
        )
        ext = binascii.unhexlify(b"ff01000100")
        host = random.choice(self.hosts)
        ext += sni(host)
        ext += b"\x00\x17\x00\x00"
        if host not in self.ticket_buf:
            self.ticket_buf[host] = os.urandom(
                (struct.unpack(">H", os.urandom(2))[0] % 17 + 8) * 16
            )
        ext += (
            b"\x00\x23"
            + struct.pack(">H", len(self.ticket_buf[host]))
            + self.ticket_buf[host]
        )
        ext += binascii.unhexlify(
            b"000d001600140601060305010503040104030301030302010203"
        )
        ext += binascii.unhexlify(b"000500050100000000")
        ext += binascii.unhexlify(b"00120000")
        ext += binascii.unhexlify(b"75500000")
        ext += binascii.unhexlify(b"000b00020100")
        ext += binascii.unhexlify(b"000a0006000400170018")
        data += pack_uint16(ext)
        data = b"\x01\x00" + pack_uint16(data)
        data = b"\x16\x03\x01" + pack_uint16(data)
        await client.sock.sendall(data)
        data = b"\x14" + self.tls_version + b"\x00\x01\x01"
        data += b"\x16" + self.tls_version + b"\x00\x20" + os.urandom(22)
        data += hmac.new(
            self.client.ns.cipher.master_key + self.session_id, data, hashlib.sha1
        ).digest()[:10]
        await client.sock.sendall(data)
