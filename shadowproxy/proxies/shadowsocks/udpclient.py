import curio

from ... import gvars
from ...utils import pack_addr, unpack_addr
from ..base.udpclient import UDPClient


class SSUDPClient(UDPClient):
    proto = "SS(UDP)"

    async def sendto(self, data, addr):
        self.target_addr = addr
        iv, encrypt = self.ns.cipher.make_encrypter()
        payload = iv + encrypt(pack_addr(addr) + data)
        await self.sock.sendto(payload, self.ns.bind_addr)

    def _unpack(self, data):
        iv = data[: self.ns.cipher.IV_SIZE]
        decrypt = self.ns.cipher.make_decrypter(iv)
        data = decrypt(data[self.ns.cipher.IV_SIZE :])
        addr, payload = unpack_addr(data)
        return addr, payload

    async def _relay(self, addr, sendfrom):
        try:
            while True:
                data, raddr = await self.sock.recvfrom(gvars.PACKET_SIZE)
                _, payload = self._unpack(data)
                await sendfrom(payload, addr)
        except curio.errors.CancelledError:
            pass
