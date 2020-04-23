import abc

import curio

from ... import gvars
from ...utils import is_global, open_connection


class ProxyBase(abc.ABC):
    target_addr = ("unknown", -1)
    client = None
    via = None

    @property
    @abc.abstractmethod
    def proto(self):
        ""

    @abc.abstractmethod
    async def _run(self):
        ""

    @property
    def target_address(self) -> str:
        return f"{self.target_addr[0]}:{self.target_addr[1]}"

    @property
    def client_address(self) -> str:
        return f"{self.client_addr[0]}:{self.client_addr[1]}"

    @property
    def via_address(self) -> str:
        if hasattr(self, "_via_address"):
            return self._via_address
        if getattr(self, "via", None):
            return self.via.bind_address
        return ""

    @property
    def remote_address(self) -> str:
        if getattr(self, "via", None):
            return self.via.bind_address
        return self.target_address

    @property
    def bind_address(self) -> str:
        return f"{self.bind_addr[0]}:{self.bind_addr[1]}"

    def __repr__(self):
        return f"{self.__class__.__name__}({self})"

    def __str__(self):
        via_address = f" -- {self.via_address}" if self.via_address else ""
        return (
            f"{self.client_address} -- {self.proto} -- {self.bind_address}"
            f"{via_address} -- {self.target_address}"
        )

    async def connect_server(self, target_addr):
        assert is_global(
            target_addr[0]
        ), f"non global target address is forbidden {target_addr}"
        source_addr = self.kwargs.get("source_addr")
        if self.via:
            via_client = self.via.new()
            self._via_address = f"{via_client.proto} -- {via_client.bind_address}"
            await via_client.connect(target_addr, source_addr)
            await via_client.init()
        else:
            via_client = await open_connection(*target_addr, source_addr=source_addr)
        gvars.logger.info(self)
        return via_client

    async def __call__(self, client, addr):
        self.client = client
        self.client_addr = addr
        try:
            async with client:
                await self._run()
        except curio.errors.TaskCancelled:
            pass
        except Exception as e:
            gvars.logger.debug(f"{self} {e}")

    async def relay(self, via_client):
        try:
            async with curio.TaskGroup() as g:
                await g.spawn(self._relay(via_client))
                await g.spawn(self._reverse_relay(via_client))
                await g.next_done(cancel_remaining=True)
        except curio.TaskGroupError as e:
            gvars.logger.debug(f"group error: {e}")

    async def _relay(self, to):
        recv = getattr(self, "recv", self.client.recv)
        while True:
            try:
                data = await recv(gvars.PACKET_SIZE)
            except (ConnectionResetError, BrokenPipeError) as e:
                gvars.logger.debug(f"{self} recv from {self.client_address} {e}")
                return
            if not data:
                break
            try:
                await to.sendall(data)
            except (ConnectionResetError, BrokenPipeError) as e:
                gvars.logger.debug(f"{self} send to {self.remote_address} {e}")
                return

    async def _reverse_relay(self, from_):
        sendall = getattr(self, "sendall", self.client.sendall)
        while True:
            try:
                data = await from_.recv(gvars.PACKET_SIZE)
            except (ConnectionResetError, BrokenPipeError) as e:
                gvars.logger.debug(f"{self} recv from {self.remote_address} {e}")
                return
            if not data:
                break
            try:
                await sendall(data)
            except (ConnectionResetError, BrokenPipeError) as e:
                gvars.logger.debug(f"{self} send to {self.client_address} {e}")
                return
