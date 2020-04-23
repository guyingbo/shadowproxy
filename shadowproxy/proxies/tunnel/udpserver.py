import pylru

from ... import gvars
from ...utils import ViaNamespace
from ..base.udpclient import UDPClient
from ..base.udpserver import UDPServerBase


class TunnelUDPServer(UDPServerBase):
    proto = "TUNNEL(UDP)"

    def __init__(self, target_addr, bind_addr, via=None, **kwargs):
        self.target_addr = target_addr
        self.bind_addr = bind_addr
        self.via = via or ViaNamespace(ClientClass=UDPClient)
        self.removed = None
        self.kwargs = kwargs

        def callback(key, value):
            self.removed = (key, value)

        self.via_clients = pylru.lrucache(256, callback)

    async def __call__(self, sock):
        while True:
            data, addr = await sock.recvfrom(gvars.PACKET_SIZE)
            if addr not in self.via_clients:
                via_client = self.via.new()
                self.via_clients[addr] = via_client
                if self.removed is not None:
                    await self.removed[1].close()
                    self.removed = None
            via_client = self.via_clients[addr]

            async def sendfrom(data, from_addr):
                await sock.sendto(data, addr)

            await via_client.sendto(data, self.target_addr)
            await via_client.relay(self.target_addr, sendfrom)

        for via_client in self.via_clients.values():
            await via_client.close()
