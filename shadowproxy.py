#!/usr/bin/env python3.6
'''Universal proxy server/client which support Socks5/HTTP/Shadowsocks/Redirect (tcp) and Shadowsocks/TProxy/Tunnel (udp) protocols.

uri syntax: {local_scheme}://[cipher:password@]{netloc}[#fragment][{=remote_scheme}://[cipher:password@]{netloc}]
support tcp schemes:
  local_scheme:   socks, ss, red, http, https
  remote_scheme:  ssr
support udp schemes:
  local_scheme:   ssudp, tproxyudp, tunneludp
  remote_scheme:  ssrudp

examples:
  python3.6 %(prog)s -v socks://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888                     # socks5 --> shadowsocks
  python3.6 %(prog)s -v http://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888                      # http   --> shadowsocks
  python3.6 %(prog)s -v red://:12345=ssr://aes-256-cfb:password@127.0.0.1:8888                      # redir  --> shadowsocks
  python3.6 %(prog)s -v ss://aes-256-cfb:password@:8888                                             # shadowsocks server (tcp)
  python3.6 %(prog)s -v ssudp://aes-256-cfb:password@:8527                                          # shadowsocks server (udp)
  python3.6 %(prog)s -v tunneludp://:8527#8.8.8.8:53=ssrudp://aes-256-cfb:password@127.0.0.1:8888   # tunnel --> shadowsocks (udp)
  sudo python3.6 %(prog)s -v tproxyudp://:8527=ssrudp://aes-256-cfb:password@127.0.0.1:8888         # tproxy --> shadowsocks (udp)
'''
from Crypto import Random
from Crypto.Cipher import AES
from hashlib import md5
from curio import spawn, tcp_server, socket, CancelledError, wait, ssl
from curio.signal import SignalSet
from functools import partial
import time
import urllib.parse
import ipaddress
import traceback
import argparse
import weakref
import signal
import struct
import types
import curio
import sys
import re
import os
__version__ = '0.1.0'
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
    try: # IPV4
        packed = b'\x01' + socket.inet_aton(host)
    except OSError:
        try: # IPV6
            packed = b'\x04' + socket.inet_pton(socket.AF_INET6, host)
        except OSError: # hostname
            packed = host.encode('ascii')
            packed = b'\x03' + len(packed).to_bytes(1, 'big') + packed
    return packed + port.to_bytes(2, 'big')


def unpack_addr(data, start=0):
    atyp = data[start]
    if atyp == 1:   # IPV4
        end = start + 5
        ipv4 = data[start+1:end]
        host = socket.inet_ntoa(ipv4)
    elif atyp == 4: # IPV6
        end = start + 17
        ipv6 = data[start:end]
        host = socket.inet_ntop(socket.AF_INET6, ipv6)
    elif atyp == 3: # hostname
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
            keybuf.append(md5( (keybuf[-1] if keybuf else b'') + password).digest())
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
        self.cipher = AES.new(self.key, mode=AES.MODE_CFB, iv=self.iv, segment_size=128)


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
                await remote_stream.client_init(self.taddr)
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
                result = await task.join()
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
                print(f'{self} error: {e}\nIt seems not been a proxy connection')
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


class SSBase:
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
        return self.decrypter.decrypt((await self._stream.read_exactly(nbytes)))

    async def read(self, maxbytes=-1):
        # patch for official shadowsocks
        # because official shadowsocks send iv as late as possible
        if not hasattr(self, 'decrypter'):
            iv = await self._stream.read_exactly(self.cipher_cls.IV_LENGTH)
            self.decrypter = self.cipher_cls(self.password, iv)
        return self.decrypter.decrypt((await self._stream.read(maxbytes)))

    async def write(self, data):
        # implement the same as official shadowsocks
        # send iv as late as possible
        if not hasattr(self, 'encrypter'):
            self.encrypter = self.cipher_cls(self.password)
            await self._stream.write(self.encrypter.iv)
        await self._stream.write(self.encrypter.encrypt(data))
        await self._stream.flush()

    async def client_init(self, taddr):
        await self._stream.write(self.encrypter.iv)
        await self.write(pack_addr(taddr))


class SSConnection(ServerBase, SSBase):
    def __init__(self, cipher_cls, password, via=None):
        self.cipher_cls = cipher_cls
        self.password = password
        self.via = via

    async def relay(self, remote_stream):
        t1 = await spawn(self._relay(self, remote_stream))
        t2 = await spawn(self._relay(remote_stream, self))
        try:
            async with wait([t1, t2]) as w:
                task = await w.next_done()
                result = await task.join()
        except CancelledError:
            pass
        #async for task in wait([t1, t2]):
        #    result = await task.join()
            #print(task, 'quit')
        #return await curio.gather([t1, t2])

    async def interact(self):
        iv = await self._stream.read_exactly(self.cipher_cls.IV_LENGTH)
        self.decrypter = self.cipher_cls(self.password, iv)
        # don't send iv from start
        # self.encrypter = self.cipher_cls(self.password)
        # await self._stream.write(self.encrypter.iv)
        self.taddr = await self.read_addr()
        remote_conn = await self.connect_remote()
        async with remote_conn:
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                await self.relay(remote_stream)
        self.on_disconnect_remote()

    async def read_addr(self):
        atyp = await self.read_exactly(1)
        if atyp == b'\x01':     # IPV4
            ipv4 = await self.read_exactly(4)
            host = socket.inet_ntoa(ipv4)
        elif atyp == b'\x04':   # IPV6
            ipv6 = await self.read_exactly(16)
            host = socket.inet_ntop(socket.AF_INET6, ipv6)
        elif atyp == b'\x03':   # hostname
            length = (await self.read_exactly(1))[0]
            hostname = await self.read_exactly(length)
            host = hostname.decode('ascii')
        else:
            raise Exception(f'unknow atyp: {atyp}') from None
        port = int.from_bytes((await self.read_exactly(2)), 'big')
        return (host, port)


class SSClient:
    def __init__(self, cipher_cls, password, host, port):
        self.cipher_cls = cipher_cls
        self.password = password
        self.raddr = (host, port)

    async def connect(self):
        return (await curio.open_connection(*self.raddr))

    def as_stream(self, conn):
        stream = SSBase()
        stream._stream = conn.as_stream()
        stream.encrypter = self.cipher_cls(self.password)
        stream.cipher_cls = self.cipher_cls
        stream.password = self.password
        return stream


class SocksConnection(ServerBase):
    def __init__(self, via=None):
        self.via = via

    async def interact(self):
        ver, nmethods = struct.unpack('!BB', (await self._stream.read_exactly(2)))
        assert ver == 5, f'unknown socks version: {ver}'
        assert nmethods != 0, f'nmethods can not be 0'
        methods = await self._stream.read_exactly(nmethods)
        if b'\x00' not in methods:
            await self._stream.write(b'\x05\xff')
            raise Exception('method not support')
        await self._stream.write(b'\x05\x00')
        ver, cmd, rsv, atyp = struct.unpack('!BBBB', (await self._stream.read_exactly(4)))
        try:
            self.command = {1: 'connect', 2: 'bind', 3: 'associate'}[cmd]
        except KeyError:
            raise Exception(f'unknown cmd: {cmd}') from None
        host, port, data = await self.read_addr(atyp)
        if self.command == 'associate':
            self.taddr = (self.laddr[0], port)
        else:
            self.taddr = (host, port)
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

    async def read_addr(self, atyp):
        if atyp == 1:   # IPV4
            data = await self._stream.read_exactly(4)
            host = socket.inet_ntoa(data)
        elif atyp == 4: # IPV6
            data = await self._stream.read_exactly(16)
            host = socket.inet_ntop(socket.AF_INET6, data)
        elif atyp == 3: # hostname
            data = (await self._stream.read_exactly(1))
            data += await self._stream.read_exactly(data[0])
            host = data[1:].decode('ascii')
        else:
            raise Exception(f'unknow atyp: {atyp}') from None
        data_port = await self._stream.read_exactly(2)
        port = int.from_bytes(data_port, 'big')
        return host, port, atyp.to_bytes(1, 'big') + data + data_port


HTTP_HEADER = re.compile('([^ ]+) +(.+?) +(HTTP/[^ ]+)')
class HTTPConnection(ServerBase):
    def __init__(self, via=None):
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
        headers = header_lines[:-4].decode().split('\r\n')
        method, path, ver = HTTP_HEADER.fullmatch(headers.pop(0)).groups()
        lines = '\r\n'.join(line for line in headers if not line.startswith('Proxy-'))
        if method == 'CONNECT':
            host, _, port = path.partition(':')
            self.taddr = (host, int(port))
        else:
            url = urllib.parse.urlparse(path)
            self.taddr = (url.hostname, url.port or 80)
            newpath = url._replace(netloc='', scheme='').geturl()
        remote_conn = await self.connect_remote()
        async with remote_conn:
            if method == 'CONNECT':
                await self._stream.write(b'HTTP/1.1 200 Connection: Established\r\n\r\n')
                remote_req_headers = None
            else:
                remote_req_headers = f'{method} {newpath} {ver}\r\n{lines}\r\n\r\n'.encode()
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                if remote_req_headers:
                    await remote_stream.write(remote_req_headers)
                await self.relay(remote_stream)
        self.on_disconnect_remote()

    async def _relay(self, rstream, wstream):
        try:
            while True:
                data = await rstream.read()
                if not data:
                    return
                if b'\r\n' in data and HTTP_HEADER.fullmatch(data.split(b'\r\n', 1)[0].decode()):
                    if b'\r\n\r\n' not in data:
                        data += await reader.read_until(b'\r\n\r\n')
                    header_lines, data = data.split(b'\r\n\r\n', 1)
                    headers = header_lines[:-4].decode().split('\r\n')
                    method, path, ver = HTTP_HEADER.fullmatch(headers.pop(0)).groups()
                    lines = '\r\n'.join(line for line in headers if not line.startswith('Proxy-'))
                    url = urllib.parse.urlparse(path)
                    self.taddr = (url.hostname, url.port or 80)
                    newpath = url._replace(netloc='', scheme='').geturl()
                    data = f'{method} {newpath} {ver}\r\n{lines}\r\n\r\n'.encode() + data
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


async def udp_server(host, port, handler_task, *, family=socket.AF_INET, reuse_address=True):
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
            self._relay_task = await spawn(self._relay(addr, listen_addr, sendfunc))

    async def _relay(self, addr, listen_addr, sendfunc):
        try:
            while True:
                data, raddr = await self.sock.recvfrom(8192)
                if verbose > 0:
                    print(f'udp: {addr[0]}:{addr[1]} <-- {listen_addr[0]}:{listen_addr[1]} <-- {raddr[0]}:{raddr[1]}')
                if sendfunc is None:
                    await sendto_from(raddr, data, addr)
                else:
                    await sendfunc(data, addr)
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
                    print(f'udp: {addr[0]}:{addr[1]} <-- {listen_addr[0]}:{listen_addr[1]} <-- {self.raddr[0]}:{self.raddr[1]} <-- {self.taddr[0]}:{self.taddr[1]}')
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
            data, ancdata, msg_flags, addr = await sock.recvmsg(8192, socket.CMSG_SPACE(24))
            #info = await socket.getaddrinfo(*addr, 0, socket.SOCK_DGRAM, socket.SOL_UDP)
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
                print(f'udp: {addr[0]}:{addr[1]} --> {listen_addr[0]}:{listen_addr[1]} --> {vaddr[0]}:{vaddr[1]} --> {taddr[0]}:{taddr[1]}')
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
                print(f'udp: {addr[0]}:{addr[1]} --> {listen_addr[0]}:{listen_addr[1]} --> {vaddr[0]}:{vaddr[1]} --> {taddr[0]}:{taddr[1]}')
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
                print(f'udp: {addr[0]}:{addr[1]} --> {listen_addr[0]}:{listen_addr[1]} --> {taddr[0]}:{taddr[1]}')
            await via_client.sendto(payload, taddr)

            async def sendto(data, taddr):
                encrypter = self.cipher_cls(self.password)
                payload = encrypter.encrypt(pack_addr(taddr)+data)
                await sock.sendto(encrypter.iv+payload, addr)

            await via_client.relay(addr, listen_addr, sendto)


protos = {
    'ss': SSConnection,
    'http': HTTPConnection,
    'https': HTTPConnection,
    'socks': SocksConnection,
    'red': RedirectConnection,
    'ssr': SSClient,
    'ssudp': SSUDPServer,
    'tproxyudp': TProxyUDPServer,
    'tunneludp': TunnelUDPServer,
    'ssrudp': SSUDPClient,
}
def uri_compile(uri):
    url = urllib.parse.urlparse(uri)
    kw = {}
    if url.scheme == 'tunneludp':
        if not url.fragment:
            raise argparse.ArgumentTypeError('destitation must be assign in tunnel udp mode, example tunneludp://:53#8.8.8.8:53')
        host, _, port = url.fragment.partition(':')
        kw['target_addr'] = (host, int(port))
    if url.scheme in ('https',):
        if not url.fragment:
            raise argparse.ArgumentTypeError('#keyfile,certfile is needed')
        keyfile, _, certfile = url.fragment.partition(',')
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        kw['ssl_context'] = ssl_context
    proto = protos[url.scheme]
    cipher, _, loc = url.netloc.rpartition('@')
    if cipher:
        cipher_cls, _, password = cipher.partition(':')
        kw['cipher_cls'] = AES256CFBCipher
        kw['password'] = password.encode()
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
        remote = uri_compile(remote_uri)
        via = partial(remote.proto, **remote.kw)
    else:
        via = None
    server_list = []
    for listen_uri in listen_uris:
        listen = uri_compile(listen_uri)
        if via:
            listen.kw['via'] = via
        host = listen.kw.pop('host')
        port = listen.kw.pop('port')
        ssl_context = listen.kw.pop('ssl_context', None)
        if listen.scheme in ('ss', 'ssudp') and 'cipher_cls' not in listen.kw:
            raise argparse.ArgumentTypeError('you need to assign cryto algorithm and password: '
                                             f'{listen.scheme}://{host}:{port}')
        if listen.scheme.endswith('udp'):
            server = udp_server(host, port, listen.proto(**listen.kw))
        else:
            server = tcp_server(host, port, ProtoFactory(listen.proto, **listen.kw), backlog=1024, ssl=ssl_context)
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
    address = ', '.join(f'{scheme}://{host}:{port}' for host, port, scheme in addrs)
    ss_filter = 'or '.join(f'dport = {port}' for host, port, scheme in addrs)
    pid = os.getpid()
    if verbose > 0:
        print(f'listen on {address} pid: {pid}')
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
            signo = await sig.wait()
            for conn in connections:
                print(f'| {conn} ({conn.stats})')
            n = len(connections)
            print('-'*15, f'{n} connections, {total_stats} ( {total_stats.get_speed()} )', '-'*15)
            total_stats.reset()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-v', dest='verbose', action='count', default=0, help='print verbose output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
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

