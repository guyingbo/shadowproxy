from Crypto import Random
from Crypto.Cipher import AES
from hashlib import md5
from curio import run, spawn, tcp_server, socket, CancelledError, queue, sleep
from functools import partial
import urllib.parse
import traceback
import argparse
import struct
import types
import curio
import sys
import re
import os
__version__ = '0.1.0'
__description__ = '''Universal proxy server/client which support Socks/SS/Redirect/HTTP protocols.
Thanks to Dabeaz's awesome curio project: https://github.com/dabeaz/curio
This project is inspired by qwj's python-proxy project(https://github.com/qwj/python-proxy), and some part of http proxy code was copy from it.

uri syntax: {local_scheme}://[cipher:password@]{netloc}[{=remote_scheme}://[cipher:password@]{netloc}]
support schemes:
  local_scheme:   socks, ss, red, http, udpss(udp)
  remote_scheme:  ss

example: python3.6 %(prog)s -v socks://:8527=ssr://aes-256-cfb:password@127.0.0.1:8888 ss://aes-256-cfb:password@:8888 udpss://aes-256-cfb:password@:8527
'''
verbose = 0


class AsyncCounter:
    def __init__(self, num=0):
        self.num = num

    async def __aenter__(self):
        self.num += 1

    async def __aexit__(self, *args):
        self.num -= 1
counter = AsyncCounter()


class wait:
    def __init__(self, tasks):
        self._initial_tasks = tasks
        self._queue = queue.Queue()
        self._tasks = None

    async def __aenter__(self):
        await self._init()
        return self

    async def __aexit__(self, ty, val, tb):
        await self.cancel_remaining()

    async def __aiter__(self):
        return self

    async def __anext__(self):
        next = await self.next_done()
        if next is None:
            raise StopAsyncIteration
        return next

    async def _init(self):
        async def wait_runner(task):
             try:
                 result = await task.join()
             except Exception:
                 pass
             await self._queue.put(task)

        self._tasks = []
        for task in self._initial_tasks:
            await spawn(wait_runner(task))
            self._tasks.append(task)

    async def next_done(self):
        if self._tasks is None:
            await self._init()
        if not self._tasks:
            return None

        task = await self._queue.get()
        self._tasks.remove(task)
        return task

    async def cancel_remaining(self):
        if self._tasks is None:
            await self._init()

        for task in self._tasks:
            await task.cancel()

        self._tasks = []


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


class ProtoFactory:
    def __init__(self, cls, *args, **kwargs):
        self.cls = cls
        self.args = args
        self.kwargs = kwargs

    async def __call__(self, client, addr):
        return await self.cls(*self.args, **self.kwargs)(client, addr)


class StreamWrapper:
    def __repr__(self):
        return '<{} {}>'.format(self.__class__.__name__, self._stream)

    async def close(self):
        await self._stream.close()

    async def __aenter__(self):
        await self._stream.__aenter__()

    async def __aexit__(self, *args):
        await self._stream.__aexit__(*args)


class ServerBase(StreamWrapper):
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
        try:
            async with client, counter:
                self.setup(client.as_stream(), addr)
                async with self:
                    await self.interact()
        except Exception as e:
            if verbose > 0:
                if hasattr(self, 'taddr'):
                    print(f'{self.taddr[0]}:{self.taddr[1]}', e)
                else:
                    print(e)
            if verbose > 1:
                traceback.print_exc()

    async def interact(self):
        raise NotImplemented

    async def connect_remote(self):
        if getattr(self, 'via', None):
            self.via_client = self.via()
            if verbose > 0:
                print(f'Connecting {self.taddr[0]}:{self.taddr[1]} '
                      f'from {self.laddr[0]}:{self.laddr[1]},{self.__proto__} '
                      f'via {self.via_client.raddr[0]}:{self.via_client.raddr[1]}')
            remote_conn = await self.via_client.connect()
        else:
            self.via_client = None
            if verbose > 0:
                print(f'Connecting {self.taddr[0]}:{self.taddr[1]} '
                      f'from {self.laddr[0]}:{self.laddr[1]},{self.__proto__}')
            remote_conn = await curio.open_connection(*self.taddr)
        return remote_conn

    async def get_remote_stream(self, remote_conn):
        if self.via_client:
            remote_stream = self.via_client.as_stream(remote_conn)
            try:
                await remote_stream.client_init(self.taddr)
            except Exception as e:
                await remote_stream.close()
                raise e
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
        except CancelledError:
            pass
        except Exception as e:
            if verbose > 0:
                print(f'{self.taddr[0]}:{self.taddr[1]} error:', e)
            if verbose > 1:
                traceback.print_exc()

    _relay2 = _relay


# Transparent proxy
class RedirectConnection(ServerBase):
    def __init__(self, via=None):
        self.via = via

    async def __call__(self, client, addr):
        SO_ORIGINAL_DST = 80
        try:
            buf = client._socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
            port, host = struct.unpack('!2xH4s8x', buf)
            self.taddr = (socket.inet_ntoa(host), port)
        except Exception as e:
            if verbose > 0:
                print("It seems not been a proxy connection:", e, 'bye.')
            await client.close()
            return
        return (await super().__call__(client, addr))

    async def interact(self):
        remote_conn = await self.connect_remote()
        async with remote_conn, counter:
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                await self.relay(remote_stream)


class SSBase(StreamWrapper):
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
        async with remote_conn, counter:
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                await self.relay(remote_stream)

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
        async with remote_conn, counter:
            await self._stream.write(self._make_resp())
            remote_stream = await self.get_remote_stream(remote_conn)
            async with remote_stream:
                await self.relay(remote_stream)

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
                    print(e)
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
        async with remote_conn, counter:
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
        except CancelledError:
            pass
        except Exception as e:
            if verbose > 0:
                print(f'{self.taddr[0]}:{self.taddr[1]} error:', e)
            if verbose > 1:
                traceback.print_exc()


async def udp_server(host, port, handler_task, *, family=socket.AF_INET, reuse_address=True):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        if reuse_address:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        async with sock:
            while True:
                data, addr = await sock.recvfrom(8192)
                try:
                    await handler_task(data, addr)
                except Exception as e:
                    if verbose > 0:
                        print(e)
                    if verbose > 1:
                        traceback.print_exc()
    except Exception:
        sock._socket.close()
        raise


class UDPSSServer:
    def __init__(self, cipher_cls, password):
        self.cipher_cls = cipher_cls
        self.password = password
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    async def __call__(self, data, addr):
        iv = data[:self.cipher_cls.IV_LENGTH]
        decrypter = self.cipher_cls(self.password, iv=iv)
        payload = decrypter.decrypt(data[self.cipher_cls.IV_LENGTH:])
        host, port, payload = unpack_addr(data)
        taddr = (host, port)
        while payload:
            nbytes = await self.sock.sendto(payload, taddr)
            payload = payload[nbytes:]


protos = {
    'ss': SSConnection,
    'http': HTTPConnection,
    'socks': SocksConnection,
    'red': RedirectConnection,
    'ssr': SSClient,
    'udpss': UDPSSServer,
}
def uri_compile(uri):
    url = urllib.parse.urlparse(uri)
    proto = protos[url.scheme]
    cipher, _, loc = url.netloc.rpartition('@')
    kw = {}
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
        if listen.scheme in ('ss', 'udpss') and 'cipher_cls' not in listen.kw:
            raise argparse.ArgumentTypeError('you need to assign cryto algorithm and password: '
                                             f'{listen.scheme}://{host}:{port}')
        if listen.scheme.startswith('udp'):
            server = udp_server(host, port, listen.proto(**listen.kw))
        else:
            server = tcp_server(host, port, ProtoFactory(listen.proto, **listen.kw), backlog=1024)
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
        print(f'lsof -p {pid} -P | grep TCP')
        print(f'ss -o "( {ss_filter} )"')
    #tasks.append((await spawn(stats())))
    await curio.gather(tasks)


async def stats():
    while True:
        print('Current connections: ', counter.num)
        await sleep(10)


def main():
    parser = argparse.ArgumentParser(description=__description__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-v', dest='verbose', action='count', default=0, help='print verbose output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--pdb', dest='pdb', action='store_true')
    parser.add_argument('server', nargs='+', type=get_server)
    args = parser.parse_args()
    global verbose
    verbose = args.verbose
    try:
        run(multi_server(*args.server), pdb=args.pdb)
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()

