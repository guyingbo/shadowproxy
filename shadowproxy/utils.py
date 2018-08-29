import types
import curio
import socket

# import signal
import ipaddress
from . import gvars

# from curio.signal import SignalEvent
# from microstats import MicroStats

local_networks = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
]
local_networks = [ipaddress.ip_network(s) for s in local_networks]


def is_local(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in nw for nw in local_networks)


def pack_bytes(data: bytes, length: int = 1) -> bytes:
    return len(data).to_bytes(length, "big") + data


def pack_addr(addr) -> bytes:
    host, port = addr
    try:  # IPV4
        packed = b"\x01" + socket.inet_aton(host)
    except OSError:
        try:  # IPV6
            packed = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
        except OSError:  # hostname
            packed = host.encode("ascii")
            packed = b"\x03" + len(packed).to_bytes(1, "big") + packed
    return packed + port.to_bytes(2, "big")


def unpack_addr(data: bytes):
    atyp = data[0]
    if atyp == 1:  # IPV4
        end = 5
        ipv4 = data[1:end]
        host = socket.inet_ntoa(ipv4)
    elif atyp == 4:  # IPV6
        end = 17
        ipv6 = data[1:end]
        host = socket.inet_ntop(socket.AF_INET6, ipv6)
    elif atyp == 3:  # hostname
        length = data[1]
        end = 2 + length
        host = data[2:end].decode("ascii")
    else:
        raise Exception(f"unknow atyp: {atyp}")
    port = int.from_bytes(data[end : end + 2], "big")
    return (host, port), data[end + 2 :]


def human_bytes(val: int) -> str:
    if val < 1024:
        return f"{val:.0f}Bytes"
    elif val < 1048576:
        return f"{val/1024:.1f}KB"
    else:
        return f"{val/1048576:.1f}MB"


def human_speed(speed: int) -> str:
    if speed < 1024:
        return f"{speed:.0f} B/s"
    elif speed < 1048576:
        return f"{speed/1024:.1f} KB/s"
    else:
        return f"{speed/1048576:.1f} MB/s"


# async def show_stats():
#     pid = os.getpid()
#     print(f"kill -USR1 {pid} to show connections")
#     stats.incr("traffic", 0)
#     sig = SignalEvent(signal.SIGUSR1)
#     while True:
#         await sig.wait()
#         sig.clear()
#         n = len(connections)
#         data = stats.flush()
#         print(
#             f'{n} connections {human_bytes(data["traffic"])} '
#             f'{human_speed(data["traffic"]/60)}'
#         )


async def open_connection(host, port, **kwargs):
    for i in range(2, -1, -1):
        try:
            return await curio.open_connection(host, port, **kwargs)
        except socket.gaierror:
            if i == 0:
                gvars.logger.debug(f"dns query failed: {host}")
                raise


def set_disposable_recv(sock, redundant):
    if redundant:
        recv = sock.recv

        async def disposable_recv(size):
            sock.recv = recv
            return redundant

        sock.recv = disposable_recv


class ViaNamespace(types.SimpleNamespace):
    @property
    def bind_address(self):
        return f"{self.bind_addr[0]}:{self.bind_addr[1]}"

    def new(self):
        return self.ClientClass(self)
