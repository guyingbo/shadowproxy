import abc


class Plugin(abc.ABC):
    name = "plugin"

    @abc.abstractmethod
    async def init_server(self, client):
        ""

    @abc.abstractmethod
    async def init_client(self, client):
        ""
