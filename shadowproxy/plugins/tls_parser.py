import binascii
import hashlib
import hmac
import os
import random
import struct
from time import time

import iofree


def pack_uint16(s):
    return len(s).to_bytes(2, "big") + s


def sni(host):
    return b"\x00\x00" + pack_uint16(pack_uint16(pack_uint16(b"\x00" + host)))


def pack_auth_data(key, session_id):
    utc_time = int(time()) & 0xFFFFFFFF
    data = struct.pack(">I", utc_time) + os.urandom(18)
    data += hmac.new(key + session_id, data, hashlib.sha1).digest()[:10]
    return data


@iofree.parser
def tls1_2_response(plugin):
    tls_version = plugin.tls_version
    with memoryview((yield from iofree.read(5))) as tls_plaintext_head:
        assert (
            tls_plaintext_head[:3] == b"\x16\x03\x03"
        ), "invalid tls head: handshake(22) protocol_version(3.1)"
        length = int.from_bytes(tls_plaintext_head[-2:], "big")
    assert length == length & 0x3FFF, f"{length} is over 2^14"
    with memoryview((yield from iofree.read(length))) as fragment:
        assert fragment[0] == 2, f"expect server_hello(2), bug got: {fragment[0]}"
        handshake_length = int.from_bytes(fragment[1:4], "big")
        server_hello = fragment[4 : handshake_length + 4]
    assert server_hello[:2] == tls_version, "expect: server_version(3.3)"
    verify_id = server_hello[2:34]
    sha1 = hmac.new(
        plugin.client.ns.cipher.master_key + plugin.session_id,
        verify_id[:-10],
        hashlib.sha1,
    ).digest()[:10]
    assert sha1 == verify_id[-10:], "hmac verify failed"
    assert server_hello[34] == 32, f"expect 32, but got {server_hello[34]}"
    # verify_id = server_hello[35:67]
    # sha1 = hmac.new(
    #     plugin.client.ns.cipher.master_key + plugin.session_id,
    #     fragment[:-10],
    #     hashlib.sha1,
    # ).digest()[:10]
    # assert sha1 == fragment[-10:], "hmac verify failed"
    while True:
        x = yield from iofree.peek(1)
        if x[0] != 22:
            break
        with memoryview((yield from iofree.read(5))) as ticket_head:
            length = int.from_bytes(ticket_head[-2:], "big")
        assert length == length & 0x3FFF, f"{length} is over 2^14"
        yield from iofree.read(length)
    yield from ChangeCipherReader(
        plugin, plugin.client.ns.cipher.master_key, plugin.session_id
    )
    yield from application_data(plugin)


@iofree.parser
def tls1_2_request(plugin):
    parser = yield from iofree.get_parser()
    tls_version = plugin.tls_version
    with memoryview((yield from iofree.read(5))) as tls_plaintext_head:
        assert (
            tls_plaintext_head[:3] == b"\x16\x03\x01"
        ), "invalid tls head: handshake(22) protocol_version(3.1)"
        length = int.from_bytes(tls_plaintext_head[-2:], "big")
    assert length == length & 0x3FFF, f"{length} is over 2^14"
    with memoryview((yield from iofree.read(length))) as fragment:
        assert fragment[0] == 1, "expect client_hello(1), but got {fragment[0]}"
        handshake_length = int.from_bytes(fragment[1:4], "big")
        client_hello = fragment[4 : handshake_length + 4]
    assert client_hello[:2] == tls_version, "expect: client_version(3.3)"
    verify_id = client_hello[2:34]
    # TODO: replay attact detect
    gmt_unix_time = int.from_bytes(verify_id[:4], "big")
    time_diff = (int(time()) & 0xFFFFFFFF) - gmt_unix_time
    assert abs(time_diff) < plugin.time_tolerance, f"expired request: {time_diff}"
    session_length = client_hello[34]
    assert session_length >= 32, "session length should be >= 32"
    session_id = client_hello[35 : 35 + session_length].tobytes()
    sha1 = hmac.new(
        plugin.server.cipher.master_key + session_id, verify_id[:22], hashlib.sha1
    ).digest()[:10]
    assert verify_id[22:] == sha1, "hmac verify failed"
    tail = client_hello[35 + session_length :]
    cipher_suites = tail[:2].tobytes()
    compression_methods = tail[2:3]
    (cipher_suites, compression_methods)
    random_bytes = pack_auth_data(plugin.server.cipher.master_key, session_id)
    server_hello = (
        tls_version
        + random_bytes
        + session_length.to_bytes(1, "big")
        + session_id
        + binascii.unhexlify(b"c02f000005ff01000100")
    )
    server_hello = b"\x02\x00" + pack_uint16(server_hello)
    server_hello = b"\x16" + tls_version + pack_uint16(server_hello)
    if random.randint(0, 8) < 1:
        ticket = os.urandom((struct.unpack(">H", os.urandom(2))[0] % 164) * 2 + 64)
        ticket = struct.pack(">H", len(ticket) + 4) + b"\x04\x00" + pack_uint16(ticket)
        server_hello += b"\x16" + tls_version + ticket
    change_cipher_spec = b"\x14" + tls_version + b"\x00\x01\x01"
    finish_len = random.choice([32, 40])
    change_cipher_spec += (
        b"\x16"
        + tls_version
        + struct.pack(">H", finish_len)
        + os.urandom(finish_len - 10)
    )
    change_cipher_spec += hmac.new(
        plugin.server.cipher.master_key + session_id, change_cipher_spec, hashlib.sha1
    ).digest()[:10]
    parser.respond(data=server_hello + change_cipher_spec)
    yield from ChangeCipherReader(plugin, plugin.server.cipher.master_key, session_id)


def ChangeCipherReader(plugin, key, session_id):
    with memoryview((yield from iofree.read(11))) as data:
        assert data[0] == 0x14, f"{data[0]} != change_cipher_spec(20) {data.tobytes()}"
        assert (
            data[1:3] == plugin.tls_version
        ), f"{data[1:3].tobytes()} != version({plugin.tls_version})"
        assert data[3:6] == b"\x00\x01\x01", "bad ChangeCipherSpec"
        assert data[6] == 0x16, f"{data[6]} != Finish(22)"
        assert (
            data[7:9] == plugin.tls_version
        ), f"{data[7:9]} != version({plugin.tls_version})"
        assert data[9] == 0x00, f"{data[9]} != Finish(0)"
        verify_len = int.from_bytes(data[9:11], "big")
        with memoryview((yield from iofree.read(verify_len))) as verify:
            sha1 = hmac.new(
                key + session_id, b"".join([data, verify[:-10]]), hashlib.sha1
            ).digest()[:10]
            assert sha1 == verify[-10:], "hmac verify failed"


@iofree.parser
def application_data(plugin):
    parser = yield from iofree.get_parser()
    while True:
        with memoryview((yield from iofree.read(5))) as data:
            assert (
                data[0] == 0x17
            ), f"{data[0]} != application_data(23) {data.tobytes()}"
            assert (
                data[1:3] == plugin.tls_version
            ), f"{data[1:3].tobytes()} != version({plugin.tls_version})"
            size = int.from_bytes(data[3:], "big")
            assert size == size & 0x3FFF, f"{size} is over 2^14"
            data = yield from iofree.read(size)
            parser.respond(result=data)
