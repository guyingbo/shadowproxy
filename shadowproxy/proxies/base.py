import abc
import curio
from .. import gvars
from ..utils import open_connection


class ProxyBase(abc.ABC):
    target_addr = ("unknown", -1)
    client = None
    via = None
    plugin = None

    @property
    @abc.abstractmethod
    def proto(self):
        pass

    @abc.abstractmethod
    async def _run(self):
        pass

    @property
    def target_address(self) -> str:
        return f"{self.target_addr[0]}:{self.target_addr[1]}"

    @property
    def client_address(self) -> str:
        return f"{self.client_addr[0]}:{self.client_addr[1]}"

    @property
    def via_address(self) -> str:
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
        if self.client is None:
            return ""
        addr = self.client.getsockname()
        return f"{addr[0]}:{addr[1]}"

    def __repr__(self):
        via_address = f" -- {self.via_address}" if self.via_address else ""
        return (
            f"{self.client_address} -- {self.proto} -- {self.bind_address}"
            f"{via_address} -- {self.target_address}"
        )

    async def connect_server(self, target_addr):
        if self.via:
            via_client = self.via.new()
            await via_client.connect(target_addr)
            return via_client
        else:
            return await open_connection(*target_addr)

    async def __call__(self, client, addr):
        self.client = client
        self.client_addr = addr
        try:
            async with client:
                if self.plugin:
                    await self.plugin.run(client)
                await self._run()
        except Exception as e:
            gvars.logger.error(e)

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
                gvars.logger.debug(f"recv from {self.client_address} {e}")
                return
            if not data:
                break
            try:
                await to.sendall(data)
            except (ConnectionResetError, BrokenPipeError) as e:
                gvars.logger.debug(f"send to {self.remote_address} {e}")
                return

    async def _reverse_relay(self, from_):
        sendall = getattr(self, "sendall", self.client.sendall)
        while True:
            try:
                data = await from_.recv(gvars.PACKET_SIZE)
            except (ConnectionResetError, BrokenPipeError) as e:
                gvars.logger.debug(f"recv from {self.remote_address} {e}")
                return
            if not data:
                break
            try:
                await sendall(data)
            except (ConnectionResetError, BrokenPipeError) as e:
                gvars.logger.debug(f"send to {self.client_address} {e}")
                return


class ClientBase(abc.ABC):
    sock = None

    def __init__(self, namespace):
        self.ns = namespace
        if hasattr(self, "_init"):
            self._init()

    async def __aenter__(self):
        if self.sock:
            await self.sock.__aenter__()
        return self

    async def __aexit__(self, et, e, tb):
        if self.sock:
            await self.sock.__aexit__(et, e, tb)

    @property
    def target_address(self) -> str:
        return f"{self.target_addr[0]}:{self.target_addr[1]}"

    @abc.abstractmethod
    async def connect(self, target_addr):
        pass

    @abc.abstractmethod
    async def recv(self, size):
        pass

    @abc.abstractmethod
    async def sendall(self, data):
        pass
