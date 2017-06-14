#!/usr/bin/env python3.6
'''An universal proxy server/client which support Socks5/HTTP/Shadowsocks/Redirect (tcp) and Shadowsocks/TProxy/Tunnel (udp) protocols.

uri syntax: {local_scheme}://[cipher:password@]{netloc}[#fragment]
            [{=remote_scheme}://[cipher:password@]{netloc}]
support tcp schemes:
  local_scheme:   socks, ss, red, http, https
  remote_scheme:  ss
support udp schemes:
  local_scheme:   ssudp, tproxyudp, tunneludp
  remote_scheme:  ssudp

examples:
  shadowproxy -v socks://:8527=ss://aes-256-cfb:password@127.0.0.1:8888                     # socks5 --> shadowsocks
  shadowproxy -v http://:8527=ss://aes-256-cfb:password@127.0.0.1:8888                      # http   --> shadowsocks
  shadowproxy -v red://:12345=ss://aes-256-cfb:password@127.0.0.1:8888                      # redir  --> shadowsocks
  shadowproxy -v ss://aes-256-cfb:password@:8888                                            # shadowsocks server (tcp)
  shadowproxy -v ssudp://aes-256-cfb:password@:8527                                         # shadowsocks server (udp)
  shadowproxy -v tunneludp://:8527#8.8.8.8:53=ssudp://aes-256-cfb:password@127.0.0.1:8888   # tunnel --> shadowsocks (udp)
  sudo shadowproxy -v tproxyudp://:8527=ssudp://aes-256-cfb:password@127.0.0.1:8888         # tproxy --> shadowsocks (udp)
'''
from Crypto import Random
from Crypto.Cipher import AES, ChaCha20, Salsa20, ARC4
from hashlib import md5
from curio import spawn, tcp_server, socket, CancelledError, wait, ssl
from curio.signal import SignalSet
from functools import partial
import time
import urllib.parse
import ipaddress
import traceback
import argparse
import resource
import weakref
import base64
import signal
import struct
import types
import curio
import sys
import re
import os
__version__ = '0.2.0'
SO_ORIGINAL_DST = 80
IP_TRANSPARENT = 19
IP_ORIGDSTADDR = 20
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR
# SOL_IPV6 = 41
# IPV6_ORIGDSTADDR = 74
# IPV6_RECVORIGDSTADDR = IPV6_ORIGDSTADDR
verbose = 0
remote_num = 0
print = partial(print, flush=True)
local_networks = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '224.0.0.0/4',
    '240.0.0.0/4',
]
local_networks = [ipaddress.ip_network(s) for s in local_networks]
# HTTP_HEADER = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)')
HTTP_LINE = re.compile(b'([^ ]+) +(.+?) +(HTTP/[^ ]+)')


def is_local(host):
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in nw for nw in local_networks)


class Stats:
    def __init__(self):
        self.reset()

    def __repr__(self):
        t = int(time.time() - self.start)
        if self.value < 1024:
            return f'{self.value:d}Bytes in {t}s'
        elif self.value < 1048576:
            return f'{self.value//1024:d}KB in {t}s'
        else:
            return f'{self.value/1048576:.1f}MB in {t}s'

    def get_speed(self):
        speed = self.value / (time.time() - self.start)
        if speed < 1024:
            return f'{speed:.0f} B/s'
        elif speed < 1048576:
            return f'{speed/1024:.0f} KB/s'
        else:
            return f'{speed/1048576:.0f} MB/s'

    def add(self, v):
        self.value += v

    def reset(self):
        self.start = time.time()
        self.value = 0


total_stats = Stats()


def pack_addr(addr):
    host, port = addr
    try:                    # IPV4
        packed = b'\x01' + socket.inet_aton(host)
    except OSError:
        try:                # IPV6
            packed = b'\x04' + socket.inet_pton(socket.AF_INET6, host)
        except OSError:     # hostname
            packed = host.encode('ascii')
            packed = b'\x03' + len(packed).to_bytes(1, 'big') + packed
    return packed + port.to_bytes(2, 'big')


def unpack_addr(data, start=0):
    atyp = data[start]
    if atyp == 1:       # IPV4
        end = start + 5
        ipv4 = data[start+1:end]
        host = socket.inet_ntoa(ipv4)
    elif atyp == 4:     # IPV6
        end = start + 17
        ipv6 = data[start:end]
        host = socket.inet_ntop(socket.AF_INET6, ipv6)
    elif atyp == 3:     # hostname
        length = data[start+1]
        end = start + 2 + length
        host = data[start+2:end].decode('ascii')
    else:
        raise Exception(f'unknow atyp: {atyp}') from None
    port = int.from_bytes(data[end:end+2], 'big')
    return (host, port), data[end+2:]


readfunc = Random.new().read


class BaseCipher:
    def get_key(self, password):
        keybuf = []
        while len(b''.join(keybuf)) < self.KEY_LENGTH:
            keybuf.append(md5(
                (keybuf[-1] if keybuf else b'') + password
            ).digest())
        return b''.join(keybuf)[:self.KEY_LENGTH]

    def __init__(self, password, iv=None):
        self.key = self.get_key(password)
        self.iv = iv if iv is not None else readfunc(self.IV_LENGTH)
        self.setup()

    def decrypt(self, data):
        return self.cipher.decrypt(data)

    def encrypt(self, data):
        return self.cipher.encrypt(data)

    def setup(self):
        pass


class AES256CFBCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16

    def setup(self):
        self.cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.iv,
                              segment_size=128)


class AES128CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 16


class AES192CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 24


class ChaCha20Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8

    def setup(self):
        self.cipher = ChaCha20.new(key=self.key, nonce=self.iv)


class Salsa20Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8

    def setup(self):
        self.cipher = Salsa20.new(key=self.key, nonce=self.iv)


class RC4Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 0

    def setup(self):
        self.cipher = ARC4.new(self.key)


class ServerBase:
    def __repr__(self):
        s = f'{self.laddr[0]}:{self.laddr[1]} --> {self.__proto__}'
        if getattr(self, 'via_client', None):
            s += f' --> {self.via_client.raddr[0]}:{self.via_client.raddr[1]}'
        if hasattr(self, 'taddr'):
            target_host, target_port = self.taddr
        else:
            target_host, target_port = 'unknown', -1
        s += f' --> {target_host}:{target_port}'
        return s

    @property
    def __proto__(self):
        proto = self.__class__.__name__[:-10]
        if getattr(self, 'command', None) == 'associate':
            proto += '(UDP)'
        return proto

    def setup(self, stream, addr):
        self._stream = stream
        self.laddr = addr

    async def __call__(self, client, addr):
        self.stats = Stats()
        try:
            async with client:
                self.setup(client.as_stream(), addr)
                async with self._stream:
                    await self.interact()
        except Exception as e:
            if verbose > 0:
                print(f'{self} error: {e}')
            if verbose > 1:
                traceback.print_exc()

    async def interact(self):
        raise NotImplemented

    async def connect_remote(self):
        global remote_num
        remote_num += 1
        if getattr(self, 'via', None):
            self.via_client = self.via()
            if verbose > 0:
                print(f'tcp: {self}')
            remote_conn = await self.via_client.connect()
        else:
            self.via_client = None
            if verbose > 0:
                print(f'tcp: {self}')
            remote_conn = await curio.open_connection(*self.taddr)
        return remote_conn

    def on_disconnect_remote(self):
        global remote_num
        remote_num -= 1
        return
        if getattr(self, 'via', None):
            if verbose > 0:
                print(f'Disconnect {self} ({self.stats})')
        else:
            if verbose > 0:
                print(f'Disconnect {self} ({self.stats})')
        # self.stats.reset()

    async def get_remote_stream(self, remote_conn):
        if self.via_client:
            remote_stream = self.via_client.as_stream(remote_conn)
            try:
                await self.via_client.init(self._stream, remote_stream,
                                           self.taddr)
            except Exception:
                await remote_stream.close()
                raise
        else:
            remote_stream = remote_conn.as_stream()
        return remote_stream

    async def relay(self, remote_stream):
        t1 = await spawn(self._relay(self._stream, remote_stream))
        t2 = await spawn(self._relay2(remote_stream, self._stream))
        try:
            async with wait([t1, t2]) as w:
                task = await w.next_done()
                await task.join()
        except CancelledError:
            pass

    async def _relay(self, rstream, wstream):
        try:
            while True:
                data = await rstream.read()
                if not data:
                    return
                await wstream.write(data)
                self.stats.add(len(data))
                total_stats.add(len(data))
        except CancelledError:
            pass
        except Exception as e:
            if verbose > 0:
                print(f'{self} error: {e}')
            if verbose > 1:
                traceback.print_exc()

    _relay2 = _relay

    async def read_addr(self):
        atyp = await self._stream.read_exactly(1)
        if atyp == b'\x01':     # IPV4
            data = await self._stream.read_exactly(4)
            host = socket.inet_ntoa(data)
        elif atyp == b'\x04':   # IPV6
            data = await self._stream.read_exactly(16)
            host = socket.inet_ntop(socket.AF_INET6, data)
        elif atyp == b'\x03':   # hostname
            data = await self._stream.read_exactly(1)
            data += await self._stream.read_exactly(data[0])
            host = data[1:].decode('ascii')
        else:
            raise Exception(f'unknow atyp: {atyp}') from None
        data_port = await self._stream.read_exactly(2)
        port = int.from_bytes(data_port, 'big')
        return (host, port), atyp + data + data_port


# Transparent proxy
class RedirectConnection(ServerBase):
    def __init__(self, via=None):
        self.via = via

    async def __call__(self, client, addr):
        try:
            buf = client._socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port, host = struct.unpack('!2xH4s8x', buf)
            self.taddr = (socket.inet_ntoa(host), port)
        except Exception as e:
            if verbose > 0:
                print(f'{self} error: {e}')
                print('--> It is not a redirect proxy connection')
            await client.close()
            return
        return (await super().__call__(client, addr))

    async def interact(self):
        remote_conn = await self.connect_remote()
        async with remote_conn:
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                await self.relay(remote_stream)
        self.on_disconnect_remote()


class SSStream:
    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, self._stream)

    async def close(self):
        await self._stream.close()

    async def __aenter__(self):
        await self._stream.__aenter__()

    async def __aexit__(self, *args):
        await self._stream.__aexit__(*args)

    async def read_exactly(self, nbytes):
        # patch for official shadowsocks
        # because official shadowsocks send iv as late as possible
        if not hasattr(self, 'decrypter'):
            iv = await self._stream.read_exactly(self.cipher_cls.IV_LENGTH)
            self.decrypter = self.cipher_cls(self.password, iv)
        return self.decrypter.decrypt(await self._stream.read_exactly(nbytes))

    async def read(self, maxbytes=-1):
        # patch for official shadowsocks
        # because official shadowsocks send iv as late as possible
        if not hasattr(self, 'decrypter'):
            iv = await self._stream.read_exactly(self.cipher_cls.IV_LENGTH)
            self.decrypter = self.cipher_cls(self.password, iv)
        return self.decrypter.decrypt(await self._stream.read(maxbytes))

    async def read_until(self, bts):
        # side-effect: read more data than you want,
        # left those data in self.buffer,
        # callers should handle this buffer themselves.
        self.buffer = buf = bytearray()
        while True:
            bts_index = buf.find(bts)
            if bts_index >= 0:
                resp = bytes(buf[:bts_index+len(bts)])
                del buf[:bts_index+len(bts)]
                return resp
            data = await self.read()
            if data == b'':
                raise EOFError('unexpect end of data')
            buf.extend(data)

    async def write(self, data):
        # implement the same as official shadowsocks
        # send iv as late as possible
        if not hasattr(self, 'encrypter'):
            self.encrypter = self.cipher_cls(self.password)
            await self._stream.write(self.encrypter.iv)
        await self._stream.write(self.encrypter.encrypt(data))
        await self._stream.flush()


class SSConnection(ServerBase):
    def __init__(self, cipher_cls, password, via=None):
        self.cipher_cls = cipher_cls
        self.password = password
        self.via = via

    def setup(self, stream, addr):
        self._stream = SSStream()
        self._stream._stream = stream
        self._stream.cipher_cls = self.cipher_cls
        self._stream.password = self.password
        self.laddr = addr

    async def interact(self):
        # don't send iv from start
        self.taddr, _ = await self.read_addr()
        remote_conn = await self.connect_remote()
        async with remote_conn:
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                await self.relay(remote_stream)
        self.on_disconnect_remote()


class SSClient:
    def __init__(self, cipher_cls, password, host, port):
        self.cipher_cls = cipher_cls
        self.password = password
        self.raddr = (host, port)

    async def connect(self):
        return (await curio.open_connection(*self.raddr))

    def as_stream(self, conn):
        stream = SSStream()
        stream._stream = conn.as_stream()
        stream.encrypter = self.cipher_cls(self.password)
        stream.cipher_cls = self.cipher_cls
        stream.password = self.password
        return stream

    async def init(self, server_stream, remote_stream, taddr):
        await remote_stream._stream.write(remote_stream.encrypter.iv)
        await remote_stream.write(pack_addr(taddr))


class HTTPClient:
    def __init__(self, auth, host, port):
        self.auth = auth
        self.raddr = (host, port)

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self.raddr[0]}:{self.raddr[1]}>'

    async def connect(self):
        return (await curio.open_connection(*self.raddr))

    def as_stream(self, conn):
        return conn.as_stream()

    async def init(self, server_stream, remote_stream, taddr):
        if taddr[1] != 443:
            await self.init_http(server_stream, remote_stream, taddr)
            return
        headers_str = (
            f'CONNECT {taddr[0]}:{taddr[1]} HTTP/1.1\r\n'
            f'Host: {taddr[0]}:{taddr[1]}\r\n'
            f'User-Agent: shadowproxy/{__version__}\r\n'
            'Proxy-Connection: Keep-Alive\r\n'
        )
        if self.auth:
            headers_str += 'Proxy-Authorization: Basic {}\r\n'.format(
                base64.b64encode(self.auth[0] + b':' + self.auth[1]).decode())
        headers_str += '\r\n'
        await remote_stream.write(headers_str.encode())
        data = await read_until(remote_stream, b'\r\n\r\n')
        if not data.startswith(b'HTTP/1.1 200 OK'):
            if verbose > 0:
                print(f'{self!r} {data}')
            if data.startswith(b'HTTP/1.1 407'):
                raise Exception(data)

    async def init_http(self, server_stream, remote_stream, taddr):
        data = await read_until(server_stream, b'\r\n\r\n')
        headers = data[:-4].split(b'\r\n')
        method, path, ver = HTTP_LINE.fullmatch(headers.pop(0)).groups()
        headers.append(b'Proxy-Connection: Keep-Alive')
        if self.auth:
            headers.append(
                b'Proxy-Authorization: Basic %s\r\n' %
                base64.b64encode(self.auth[0] + b':' + self.auth[1]))
        url = urllib.parse.urlparse(path)
        newpath = url._replace(scheme=b'http',
                               netloc=('%s:%s' % taddr).encode()).geturl()
        data = b'%b %b %b\r\n%b\r\n\r\n' % (
                method, newpath, ver, b'\r\n'.join(headers))
        await remote_stream.write(data)
        if hasattr(server_stream, 'buffer') and server_stream.buffer:
            await remote_stream.write(server_stream.buffer)
            del server_stream.buffer[:]


async def read_until(stream, bts):
    if hasattr(stream, 'read_until'):
        return await stream.read_until(bts)
    buf = stream._buffer
    while True:
        bts_index = buf.find(bts)
        if bts_index >= 0:
            resp = bytes(buf[:bts_index+len(bts)])
            del buf[:bts_index+len(bts)]
            return resp
        data = await stream._read(65536)
        if data == b'':
            raise EOFError('unexpect end of data')
        buf.extend(data)


class SocksConnection(ServerBase):
    def __init__(self, auth=None, via=None):
        self.auth = auth
        self.via = via

    async def interact(self):
        ver, nmethods = struct.unpack(
                '!BB', await self._stream.read_exactly(2))
        assert ver == 5, f'unknown socks version: {ver}'
        assert nmethods != 0, f'nmethods can not be 0'
        methods = await self._stream.read_exactly(nmethods)
        if self.auth and b'\x02' not in methods:
            await self._stream.write(b'\05\xff')
            raise Exception('server need auth')
        elif b'\x00' not in methods:
            await self._stream.write(b'\x05\xff')
            raise Exception('method not support')
        if self.auth:
            await self._stream.write(b'\x05\x02')
            auth_ver, username_length = struct.unpack(
                    '!BB', await self._stream.read_exactly(2))
            assert auth_ver == 1
            username = await self._stream.read_exactly(username_length)
            password_length = (await self._stream.read_exactly(1))[0]
            password = await self._stream.read_exactly(password_length)
            if (username, password) != self.auth:
                await self._stream.write(b'\x01\x01')
                raise Exception('auth failed')
            else:
                await self._stream.write(b'\x01\x00')
        else:
            await self._stream.write(b'\x05\x00')
        ver, cmd, rsv = struct.unpack(
                '!BBB', await self._stream.read_exactly(3))
        try:
            self.command = {1: 'connect', 2: 'bind', 3: 'associate'}[cmd]
        except KeyError:
            raise Exception(f'unknown cmd: {cmd}') from None
        self.taddr, data = await self.read_addr()
        if self.command == 'associate':
            self.taddr = (self.laddr[0], self.taddr[1])
        return await getattr(self, 'cmd_' + self.command)()

    async def cmd_connect(self):
        remote_conn = await self.connect_remote()
        async with remote_conn:
            await self._stream.write(self._make_resp())
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                await self.relay(remote_stream)
        self.on_disconnect_remote()

    async def cmd_associate(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(('', 0))
            host, port = sock.getsockname()
            async with sock:
                await self._stream.write(self._make_resp(host=host, port=port))
                task = await spawn(self.relay_udp(sock))
                while True:
                    data = await self._stream.read()
                    if not data:
                        await task.cancel()
                        return
                    if verbose > 0:
                        print('receive unexpect data:', data)
        except:
            sock._socket.close()

    async def relay_udp(self, sock):
        while True:
            try:
                data, addr = await sock.recvfrom(8192)
                print(data, addr, self.taddr)
                if addr == self.taddr:
                    taddr, data = unpack_addr(data, 3)
                    address = taddr
                else:
                    address = self.taddr
                while data:
                    nbytes = await sock.sendto(data, address)
                    data = data[nbytes:]
            except CancelledError:
                return
            except Exception as e:
                if verbose > 0:
                    print(f'{self} error: {e}')
                if verbose > 1:
                    traceback.print_exc()

    def _make_resp(self, code=0, host='0.0.0.0', port=0):
        return b'\x05' + code.to_bytes(1, 'big') + b'\x00' + \
               pack_addr((host, port))


class HTTPConnection(ServerBase):
    def __init__(self, auth=None, via=None):
        self.auth = auth
        self.via = via

    async def read_until(self, bts):
        buf = self._stream._buffer
        while True:
            bts_index = buf.find(bts)
            if bts_index >= 0:
                resp = bytes(buf[:bts_index+len(bts)])
                del buf[:bts_index+len(bts)]
                return resp
            data = await self._stream._read(65536)
            if data == b'':
                raise EOFError('unexpect end of data')
            buf.extend(data)

    async def interact(self):
        header_lines = await self.read_until(b'\r\n\r\n')
        headers = header_lines[:-4].split(b'\r\n')
        method, path, ver = HTTP_LINE.fullmatch(headers.pop(0)).groups()
        lines = b'\r\n'.join(
                line for line in headers if not line.startswith(b'Proxy-'))
        headers = dict(line.split(b': ', 1) for line in headers)
        if self.auth:
            pauth = headers.get(b'Proxy-Authorization', None)
            httpauth = b'Basic ' + base64.b64encode(b':'.join(self.auth))
            if httpauth != pauth:
                await self._stream.write(
                    ver + b' 407 Proxy Authentication Required\r\n'
                    b'Connection: close\r\n'
                    b'Proxy-Authenticate: Basic realm="simple"\r\n\r\n')
                raise Exception('Unauthorized HTTP Request')
        if method == b'CONNECT':
            host, _, port = path.partition(b':')
            self.taddr = (host.decode(), int(port))
        else:
            url = urllib.parse.urlparse(path)
            self.taddr = (url.hostname.decode(), url.port or 80)
            newpath = url._replace(netloc=b'', scheme=b'').geturl()
        remote_conn = await self.connect_remote()
        async with remote_conn:
            if method == b'CONNECT':
                await self._stream.write(
                        b'HTTP/1.1 200 Connection: Established\r\n\r\n')
                remote_req_headers = None
            else:
                remote_req_headers = b'%s %s %s\r\n%s\r\n\r\n' % (
                        method, newpath, ver, lines)
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                if remote_req_headers:
                    await remote_stream.write(remote_req_headers)
                await self.relay(remote_stream)
        self.on_disconnect_remote()

    # async def interact_old(self):
    #     header_lines = await self.read_until(b'\r\n\r\n')
    #     headers = header_lines[:-4].decode().split('\r\n')
    #     method, path, ver = HTTP_HEADER.fullmatch(headers.pop(0)).groups()
    #     lines = '\r\n'.join(
    #             line for line in headers if not line.startswith('Proxy-'))
    #     headers = dict(line.split(': ', 1) for line in headers)
    #     if self.auth:
    #         pauth = headers.get('Proxy-Authorization', None)
    #         httpauth = 'Basic ' + base64.b64encode(
    #                 b':'.join(self.auth)).decode()
    #         if httpauth != pauth:
    #             await self._stream.write(
    #                 f'{ver} 407 Proxy Authentication Required\r\n'
    #                 'Connection: close\r\n'
    #                 'Proxy-Authenticate: '
    #                 'Basic realm="simple"\r\n\r\n'.encode()
    #             )
    #             raise Exception('Unauthorized HTTP Request')
    #     if method == 'CONNECT':
    #         host, _, port = path.partition(':')
    #         self.taddr = (host, int(port))
    #     else:
    #         url = urllib.parse.urlparse(path)
    #         self.taddr = (url.hostname, url.port or 80)
    #         newpath = url._replace(netloc='', scheme='').geturl()
    #     remote_conn = await self.connect_remote()
    #     async with remote_conn:
    #         if method == 'CONNECT':
    #             await self._stream.write(
    #                     b'HTTP/1.1 200 Connection: Established\r\n\r\n')
    #             remote_req_headers = None
    #         else:
    #             remote_req_headers = f'{method} {newpath} {ver}\r\n'\
    #                     f'{lines}\r\n\r\n'.encode()
    #         remote_stream = await self.get_remote_stream(remote_conn)
    #         async with remote_stream:
    #             if remote_req_headers:
    #                 await remote_stream.write(remote_req_headers)
    #             await self.relay(remote_stream)
    #     self.on_disconnect_remote()


async def udp_server(host, port, handler_task, *,
                     family=socket.AF_INET, reuse_address=True):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        if reuse_address:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        async with sock:
            await handler_task(sock)
    except Exception:
        sock._socket.close()
        raise


def Sendto():
    socks = weakref.WeakValueDictionary()

    async def sendto_from(bind_addr, data, addr):
        try:
            if bind_addr not in socks:
                sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sender.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                sender.bind(bind_addr)
                socks[bind_addr] = sender
            sender = socks[bind_addr]
            async with sender:
                await sender.sendto(data, addr)
        except OSError as e:
            if verbose > 0:
                print(e, bind_addr)
    return sendto_from


sendto_from = Sendto()


class UDPClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._relay_task = None

    async def sendto(self, data, addr):
        await self.sock.sendto(data, addr)

    async def relay(self, addr, listen_addr, sendfunc=None):
        if self._relay_task is None:
            self._relay_task = await spawn(
                    self._relay(addr, listen_addr, sendfunc))

    async def _relay(self, addr, listen_addr, sendfunc):
        try:
            while True:
                data, raddr = await self.sock.recvfrom(8192)
                if verbose > 0:
                    print(f'udp: {addr[0]}:{addr[1]} <-- '
                          f'{listen_addr[0]}:{listen_addr[1]} <-- '
                          f'{raddr[0]}:{raddr[1]}')
                if sendfunc is None:
                    await sendto_from(raddr, data, addr)
                else:
                    await sendfunc(data, raddr)
        except CancelledError:
            pass

    async def close(self):
        await self._relay_task.cancel()
        await self.sock.close()


class SSUDPClient(UDPClient):
    def __init__(self, cipher_cls, password, host, port):
        self.cipher_cls = cipher_cls
        self.password = password
        self.raddr = (host, port)
        super().__init__()

    async def sendto(self, data, addr):
        self.taddr = addr
        encrypter = self.cipher_cls(self.password)
        payload = encrypter.iv + encrypter.encrypt(pack_addr(addr) + data)
        await self.sock.sendto(payload, self.raddr)

    def _unpack(self, data):
        iv = data[:self.cipher_cls.IV_LENGTH]
        cipher = self.cipher_cls(self.password, iv)
        data = cipher.decrypt(data[self.cipher_cls.IV_LENGTH:])
        addr, payload = unpack_addr(data)
        return payload, addr

    async def _relay(self, addr, listen_addr, sendfunc):
        try:
            while True:
                data, _ = await self.sock.recvfrom(8192)
                payload, taddr = self._unpack(data)
                if verbose > 0:
                    print(f'udp: {addr[0]}:{addr[1]} <-- '
                          f'{listen_addr[0]}:{listen_addr[1]} <-- '
                          f'{self.raddr[0]}:{self.raddr[1]} <-- '
                          f'{self.taddr[0]}:{self.taddr[1]}')
                if sendfunc is None:
                    await sendto_from(self.taddr, payload, addr)
                else:
                    await sendfunc(payload, addr)
        except CancelledError:
            pass


class TProxyUDPServer:
    def __init__(self, via=None):
        self.via = via
        self.removed = None

        def callback(key, value):
            self.removed = (key, value)
        import pylru
        self.addr2client = pylru.lrucache(256, callback)

    @staticmethod
    def get_origin_dst(ancdata):
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == IP_RECVORIGDSTADDR:
                family, port, ip = struct.unpack('!HH4s8x', cmsg_data)
                return (socket.inet_ntoa(ip), port)

    async def __call__(self, sock):
        sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, True)
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        listen_addr = sock.getsockname()
        while True:
            data, ancdata, msg_flags, addr = await sock.recvmsg(
                    8192, socket.CMSG_SPACE(24))
            # info = await socket.getaddrinfo(
            #         *addr, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
            taddr = self.get_origin_dst(ancdata)
            if taddr is None:
                if verbose > 0:
                    print('can not recognize the original destination')
                continue
            elif is_local(taddr[0]):
                if verbose > 0:
                    print(f'local addresses are forbidden: {taddr[0]}')
                continue
            if addr not in self.addr2client:
                via_client = self.via()
                self.addr2client[addr] = via_client
                if self.removed is not None:
                    await self.removed[1].close()
                    self.removed = None
            via_client = self.addr2client[addr]
            vaddr = via_client.raddr
            if verbose > 0:
                print(f'udp: {addr[0]}:{addr[1]} --> '
                      f'{listen_addr[0]}:{listen_addr[1]} --> '
                      f'{vaddr[0]}:{vaddr[1]} --> {taddr[0]}:{taddr[1]}')
            await via_client.sendto(data, taddr)
            await via_client.relay(addr, listen_addr)


class TunnelUDPServer:
    def __init__(self, target_addr, via=None):
        self.taddr = target_addr
        self.via = via
        self.removed = None

        def callback(key, value):
            self.removed = (key, value)
        import pylru
        self.addr2client = pylru.lrucache(256, callback)

    async def __call__(self, sock):
        taddr = self.taddr
        listen_addr = sock.getsockname()
        while True:
            data, addr = await sock.recvfrom(8192)
            if addr not in self.addr2client:
                via_client = self.via()
                self.addr2client[addr] = via_client
                if self.removed is not None:
                    await self.removed[1].close()
                    self.removed = None
            via_client = self.addr2client[addr]
            vaddr = via_client.raddr
            if verbose > 0:
                print(f'udp: {addr[0]}:{addr[1]} --> '
                      f'{listen_addr[0]}:{listen_addr[1]} --> '
                      f'{vaddr[0]}:{vaddr[1]} --> {taddr[0]}:{taddr[1]}')
            await via_client.sendto(data, taddr)
            await via_client.relay(addr, listen_addr, sock.sendto)


class SSUDPServer:
    def __init__(self, cipher_cls, password):
        self.via = UDPClient
        self.cipher_cls = cipher_cls
        self.password = password
        self.removed = None

        def callback(key, value):
            self.removed = (key, value)
        import pylru
        self.addr2client = pylru.lrucache(256, callback)

    async def __call__(self, sock):
        listen_addr = sock.getsockname()
        while True:
            data, addr = await sock.recvfrom(8192)
            if len(data) <= self.cipher_cls.IV_LENGTH:
                continue
            if addr not in self.addr2client:
                via_client = self.via()
                self.addr2client[addr] = via_client
                if self.removed is not None:
                    await self.removed[1].close()
                    self.removed = None
            via_client = self.addr2client[addr]
            iv = data[:self.cipher_cls.IV_LENGTH]
            decrypter = self.cipher_cls(self.password, iv=iv)
            data = decrypter.decrypt(data[self.cipher_cls.IV_LENGTH:])
            taddr, payload = unpack_addr(data)
            if verbose > 0:
                print(f'udp: {addr[0]}:{addr[1]} --> '
                      f'{listen_addr[0]}:{listen_addr[1]} --> '
                      f'{taddr[0]}:{taddr[1]}')
            await via_client.sendto(payload, taddr)

            async def sendto(data, taddr):
                encrypter = self.cipher_cls(self.password)
                payload = encrypter.encrypt(pack_addr(taddr)+data)
                await sock.sendto(encrypter.iv+payload, addr)

            await via_client.relay(addr, listen_addr, sendto)


server_protos = {
    'ss': SSConnection,
    'http': HTTPConnection,
    'https': HTTPConnection,
    'socks': SocksConnection,
    'red': RedirectConnection,
    'ssudp': SSUDPServer,
    'tproxyudp': TProxyUDPServer,
    'tunneludp': TunnelUDPServer,
}
client_protos = {
    'ss': SSClient,
    'ssr': SSClient,
    'ssudp': SSUDPClient,
    'ssrudp': SSUDPClient,
    'http': HTTPClient,
}
ciphers = {
    'aes-256-cfb': AES256CFBCipher,
    'aes-128-cfb': AES128CFBCipher,
    'aes-192-cfb': AES192CFBCipher,
    'chacha20': ChaCha20Cipher,
    'salsa20': Salsa20Cipher,
    'rc4': RC4Cipher,
}


def uri_compile(uri, is_server):
    url = urllib.parse.urlparse(uri)
    kw = {}
    if url.scheme == 'tunneludp':
        if not url.fragment:
            raise argparse.ArgumentTypeError(
                    'destitation must be assign in tunnel udp mode, '
                    'example tunneludp://:53#8.8.8.8:53')
        host, _, port = url.fragment.partition(':')
        kw['target_addr'] = (host, int(port))
    if url.scheme in ('https',):
        if not url.fragment:
            raise argparse.ArgumentTypeError('#keyfile,certfile is needed')
        keyfile, _, certfile = url.fragment.partition(',')
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        kw['ssl_context'] = ssl_context
    proto = server_protos[url.scheme] if is_server else \
        client_protos[url.scheme]
    cipher, _, loc = url.netloc.rpartition('@')
    if cipher:
        cipher_cls, _, password = cipher.partition(':')
        if url.scheme.startswith('ss'):
            kw['cipher_cls'] = ciphers[cipher_cls]
            kw['password'] = password.encode()
        elif url.scheme in ('http', 'https', 'socks'):
            kw['auth'] = (cipher_cls.encode(), password.encode())
        else:
            pass
    if loc:
        kw['host'], _, port = loc.partition(':')
        kw['port'] = int(port) if port else 1080
    return types.SimpleNamespace(proto=proto, scheme=url.scheme, kw=kw)


def get_server(uri):
    listen_uris, _, remote_uri = uri.partition('=')
    listen_uris = listen_uris.split(',')
    if not listen_uris:
        raise ValueError('no server found')
    if remote_uri:
        remote = uri_compile(remote_uri, False)
        via = partial(remote.proto, **remote.kw)
    else:
        via = None
    server_list = []
    for listen_uri in listen_uris:
        listen = uri_compile(listen_uri, True)
        if via:
            listen.kw['via'] = via
        host = listen.kw.pop('host')
        port = listen.kw.pop('port')
        ssl_context = listen.kw.pop('ssl_context', None)
        if listen.scheme in ('ss', 'ssudp') and 'cipher_cls' not in listen.kw:
            raise argparse.ArgumentTypeError(
                    'you need to assign cryto algorithm and password: '
                    f'{listen.scheme}://{host}:{port}')
        if listen.scheme.endswith('udp'):
            server = udp_server(host, port, listen.proto(**listen.kw))
        else:
            server = tcp_server(host, port, ProtoFactory(
                listen.proto, **listen.kw), backlog=1024, ssl=ssl_context)
        server_list.append((server, (host, port), listen.scheme))
    return server_list


async def multi_server(*servers):
    tasks = []
    addrs = []
    for server_list in servers:
        for server, addr, scheme in server_list:
            task = await spawn(server)
            tasks.append(task)
            addrs.append((*addr, scheme))
    address = ', '.join(
            f'{scheme}://{host}:{port}' for host, port, scheme in addrs)
    ss_filter = 'or '.join(f'dport = {port}' for host, port, scheme in addrs)
    pid = os.getpid()
    if verbose > 0:
        print(f'{__name__}/{__version__} listen on {address} pid: {pid}')
        print(f'sudo lsof -p {pid} -P | grep -e TCP -e STREAM')
        print(f'ss -o "( {ss_filter} )"')
    tasks.append((await spawn(show_stats())))
    await curio.gather(tasks)


connections = weakref.WeakSet()


def ProtoFactory(cls, *args, **kwargs):
    async def client_handler(client, addr):
        handler = cls(*args, **kwargs)
        connections.add(handler)
        return await handler(client, addr)
    return client_handler


async def show_stats():
    pid = os.getpid()
    print(f'kill -USR1 {pid} to show connections')
    while True:
        async with SignalSet(signal.SIGUSR1) as sig:
            await sig.wait()
            for conn in connections:
                print(f'| {conn} ({conn.stats})')
            n = len(connections)
            print('-'*15,
                  f'{n} connections, {total_stats} '
                  f'( {total_stats.get_speed()} )',
                  '-'*15)
            total_stats.reset()


def main():
    parser = argparse.ArgumentParser(
            description=__doc__,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-v', dest='verbose', action='count', default=0,
                        help='print verbose output')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {__version__}')
    parser.add_argument('--monitor', dest='monitor', action='store_true')
    parser.add_argument('server', nargs='+', type=get_server)
    args = parser.parse_args()
    global verbose
    verbose = args.verbose
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (50000, 50000))
    except Exception as e:
        print('Require root permission to allocate resources')
    kernel = curio.Kernel(with_monitor=args.monitor)
    try:
        kernel.run(multi_server(*args.server))
    except Exception as e:
        traceback.print_exc()
        for k, v in kernel._selector.get_map().items():
            print(k, v, file=sys.stderr)
        for conn in connections:
            print('|', conn, file=sys.stderr)
    except KeyboardInterrupt:
        kernel.run(shutdown=True)
        print()


if __name__ == '__main__':
    main()
