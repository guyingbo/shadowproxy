#!/usr/bin/env python3
# references:
# rfc1928(socks5): https://www.ietf.org/rfc/rfc1928.txt
# asyncio-socks5 https://github.com/RobberPhex/asyncio-socks5
# head
# +----+----------+----------+
# |VER | NMETHODS | METHODS  |
# +----+----------+----------+
# | 1  |    1     | 1 to 255 |
# +----+----------+----------+
# tcp relay command
# +----+-----+-------+------+----------+----------+
# |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+
# tcp relay command reply
# +----+-----+-------+------+----------+----------+
# |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+
# udp relay command and reply
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+
from struct import Struct, pack
import asyncio
import logging
loop = asyncio.get_event_loop()
logger = logging.getLogger()
skip_network = [
    '127.0.0.1/32',
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '100.64.0.0/10',
    'localhost',
    '*.local'
]


BREAK = True
st_hello = Struct('!BB')
st_request_head = Struct('!BBBB')
st_port = Struct('!H')
st_ipv4 = Struct('!BBBB')
st_reply = Struct('!BBBBBBBBH')
st_udp_head = Struct('!HBB')
st_udp_reply = Struct('!HBBBBBBH')
class Socks5ServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport
        self._buffer = bytearray()
        self.state = 'hello'
        self._size = st_hello.size
        self.proxy = False

    def connection_lost(self, *args):
        self.transport.close()

    def data_received(self, data):
        #print(data)
        if self._size == 0:
            asyncio.ensure_future(self.send_data(data))
            return
        self._buffer.extend(data)
        while True:
            size = self._size
            if len(self._buffer) < size:
                break
            r = getattr(self, 'wait_'+self.state)()
            del self._buffer[:size]
            if r == BREAK:
                break

    def wait_hello(self):
        ver, nmethods = st_hello.unpack_from(self._buffer)
        if ver != 5:
            self.transport.close()
            return BREAK
        if nmethods == 0:
            self.transport.close()
            return BREAK
        self.state = 'nmethods'
        self._size = nmethods

    def wait_nmethods(self):
        data = self._buffer[:self._size]
        if b'\x00' not in data:
            self.transport.write(b'\x05\xff')
            self.transport.close()
            return BREAK
        self.transport.write(b'\x05\x00')
        self.state = 'request_head'
        self._size = st_request_head.size

    def wait_request_head(self):
        ver, self.cmd, rsv, atyp = st_request_head.unpack_from(self._buffer)
        if self.cmd == 1:
            self.command = 'connect'
        elif self.cmd == 2:
            self.command = 'bind'
        elif self.cmd == 3:
            self.command = 'associate'
        else:
            self.transport.close()
            return BREAK
        if atyp == 1:
            self.state = 'ipv4'
            self._size = 4
        elif atyp == 3:
            self.state = 'domain_size'
            self._size = 1
        elif atyp == 4:
            self.state = 'ipv6'
            self._size = 16
        else:
            self.transport.close()
            return BREAK

    def wait_ipv4(self):
        self.resp = pack('!B', 1) + self._buffer[:self._size]
        ipv4_list = st_ipv4.unpack_from(self._buffer)
        self.host = '.'.join([str(i) for i in ipv4_list])
        self.state = 'port'
        self._size = st_port.size

    def wait_domain_size(self):
        domain_size, = Struct('!B').unpack_from(self._buffer)
        if domain_size < 1:
            self.transport.close()
            return BREAK
        self.state = 'domain_name'
        self._size = domain_size

    def wait_domain_name(self):
        self.host = self._buffer[:self._size]
        self.resp = pack('!BB', 3, self._size) + self.host
        self.state = 'port'
        self._size = st_port.size

    def wait_ipv6(self):
        self.resp = pack('!B', 4) + self._buffer[:self._size]
        segments = [self._buffer[i:i+4] for i in range(4)]
        self.host = ':'.join(a.hex() for a in segments)
        self.state = 'port'
        self._size = st_port.size

    def wait_port(self):
        self.port, = st_port.unpack_from(self._buffer)
        if self.command in ('connect', 'associate'):
            self.waiter = asyncio.ensure_future(getattr(self, 'cmd_'+self.command)())
        else:
            data = st_reply.pack(5, 7, 0, 1, 127, 0, 0, 1, self.port)
            self.transport.write(data)
        self._size = 0
        return BREAK

    async def cmd_connect(self):
        #print(self.host, self.port)
        try:
            self.client_transport, protocol = await loop.create_connection(lambda: TCPRelayProtocol(self.transport), str(self.host), self.port)
        except Exception as e:
            logger.error('tcp error {}:{}'.format(self.host, self.port), exc_info=True)
            data = pack('!BBB', 5, 1, 0) + self.resp + st_port.pack(self.port)
            self.transport.write(data)
            self.transport.close()
        else:
            ip, port = self.client_transport.get_extra_info('sockname')
            ipv4 = [int(i) for i in ip.split('.')]
            data = st_reply.pack(5, 0, 0, 1, *ipv4, self.port)
            self.transport.write(data)
            self.client_transport.write(self._buffer)
            del self._buffer[:]
            return self.client_transport

    async def cmd_associate(self):
        ip = '0.0.0.0'
        host = self.transport.get_extra_info('peername')[0]
        addr = (host, self.port)
        try:
            transport, protocol = await loop.create_datagram_endpoint(lambda: UDPRelayProtocol(addr), local_addr=(ip, 0))
        except Exception as e:
            logger.error('udp error {}:{}'.format(ip, 0), exc_info=True)
            data = st_reply.pack(5, 1, 0, 1, 0, 0, 0, 0, 0)
            self.transport.write(data)
            return
        bind_addr = transport.get_extra_info('sockname')
        logger.debug('Socks5 UDP Server running on: {}'.format(bind_addr))
        data = st_reply.pack(5, 0, 0, 1, 0, 0, 0, 0, bind_addr[1])
        self.transport.write(data)
        self._size = 0
        return self.transport

    async def send_data(self, data):
        if hasattr(self, 'waiter'):
            transport = await self.waiter
            if transport:
                transport.write(data)


class TCPRelayProtocol(asyncio.Protocol):
    def __init__(self, server_transport):
        self.server_transport = server_transport

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        #logger.debug('receive data with length {}'.format(len(data)))
        self.server_transport.write(data)

    def connection_lost(self, exc):
        if exc:
            logger.debug('connection_lost {0}'.format(exc))
        self.transport.close()
        self.server_transport.close()


class UDPRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, addr):
        self.addr = addr

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        logger.info('udp data from {1}:{0}'.format(data, addr))
        if addr == self.addr:
            return self.do_relay(data, addr)
        ipv4 = [int(i) for i in addr[0].split('.')]
        reply = st_udp_reply.pack(0, 0, 1, *ipv4, addr[1]) + data
        #print('-'*10, self.addr, reply)
        self.transport.sendto(reply, self.addr)

    def do_relay(self, data, addr):
        if len(data) < st_udp_head.size:
            return
        rsv, frag, atyp = st_udp_head.unpack_from(data)
        data = data[4:]
        if atyp == 1 and len(data) >= st_ipv4.size:
            ipv4_list = st_ipv4.unpack_from(data)
            host = '.'.join([str(i) for i in ipv4_list])
            data = data[4:]
        elif atyp == 3 and len(data) >= 1:
            length, = Struct('!B').unpack_from(data)
            data = data[1:]
            if length == 0 or len(data) < length:
                return
            host = data[:length]
            data = data[length:]
        elif atyp == 4 and len(data) >= 16:
            host = data[:16]
            data = data[16:]
        else:
            return
        if len(data) < st_port.size:
            return
        port, = st_port.unpack_from(data)
        real_data = data[2:]
        #print('sendto:', real_data, host, port)
        self.transport.sendto(real_data, (host, port))

    def error_received(self, exc):
        print(exc)

    def connection_lost(self, exc):
        self.transport.close()


def main():
    coro = loop.create_server(Socks5ServerProtocol, '127.0.0.1', 1081)
    server = loop.run_until_complete(coro)
    print('Socks5 Server running on: {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
