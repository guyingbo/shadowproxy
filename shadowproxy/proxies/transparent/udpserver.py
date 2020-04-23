import struct
import weakref

import pylru
from curio import socket

from ...utils import ViaNamespace, is_global
from ..base.udpclient import UDPClient
from ..base.udpserver import UDPServerBase

IP_TRANSPARENT = 19
IP_ORIGDSTADDR = 20
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR


class TransparentUDPServer(UDPServerBase):
    proto = "RED(UDP)"

    def __init__(self, bind_addr, via=None, **kwargs):
        self.bind_addr = bind_addr
        self.via = via or ViaNamespace(ClientClass=UDPClient)
        self.removed = None
        self.kwargs = kwargs

        def callback(key, value):
            self.removed = (key, value)

        self.via_clients = pylru.lrucache(256, callback)
        self.bind_socks = weakref.WeakValueDictionary()

    @staticmethod
    def get_origin_dst(ancdata):
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == IP_RECVORIGDSTADDR:
                family, port, ip = struct.unpack("!HH4s8x", cmsg_data)
                return (socket.inet_ntoa(ip), port)

    async def __call__(self, sock):
        sock.setsockopt(socket.SOL_IP, IP_RECVORIGDSTADDR, True)
        sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        while True:
            data, ancdata, msg_flags, addr = await sock.recvmsg(
                8192, socket.CMSG_SPACE(24)
            )
            target_addr = self.get_origin_dst(ancdata)
            if target_addr is None:
                continue
            elif not is_global(target_addr[0]):
                continue
            if addr not in self.via_clients:
                via_client = self.via.new()
                self.via_clients[addr] = via_client
                if self.removed is not None:
                    await self.removed[1].close()
                    self.removed = None
            via_client = self.via_clients[addr]
            await via_client.sendto(data, target_addr)

            async def sendfrom(data, from_addr):
                if from_addr not in self.bind_socks:
                    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sender.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
                    sender.bind(from_addr)
                    self.bind_socks[from_addr] = sender
                sender = self.bind_socks[from_addr]
                await sender.sendto(data, addr)

            await via_client.relay(target_addr, sendfrom)

        for via_client in self.via_clients.values():
            await via_client.close()
        for sender in self.bind_socks.values():
            await sender.close()
