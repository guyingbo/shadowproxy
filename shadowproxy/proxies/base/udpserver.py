import abc


class UDPServerBase(abc.ABC):
    @property
    @abc.abstractmethod
    def proto(self):
        ""

    @abc.abstractmethod
    async def __call__(self, sock):
        ""
