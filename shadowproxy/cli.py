import os
import types
import curio
import base64
import weakref
import logging
import argparse
import resource
import traceback
from curio import ssl
from curio import socket
from curio.network import run_server
from urllib import parse
from . import gvars
from .ciphers import ciphers
from . import __version__, __doc__ as desc
from .proxies import server_protos, via_protos
from .plugins import plugins

connections = weakref.WeakSet()


def TcpProtoFactory(cls, *args, **kwargs):
    async def client_handler(client, addr):
        handler = cls(*args, **kwargs)
        connections.add(handler)
        return await handler(client, addr)

    return client_handler


class ViaNamespace(types.SimpleNamespace):
    @property
    def bind_address(self):
        return f"{self.bind_addr[0]}:{self.bind_addr[1]}"

    def new(self):
        return self.ClientClass(self)


def get_server(uri, is_via=False):
    url = parse.urlparse(uri)
    kwargs = {}
    ssl_context = None
    if url.scheme in ("https",):
        if not url.fragment:
            raise argparse.ArgumentTypeError("#keyfile,certfile is needed")
        keyfile, _, certfile = url.fragment.partition(",")
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    proto = via_protos[url.scheme] if is_via else server_protos[url.scheme]
    userinfo, _, loc = url.netloc.rpartition("@")
    if userinfo:
        if ":" not in userinfo:
            userinfo = base64.b64decode(userinfo).decode("ascii")
        cipher_name, _, password = userinfo.partition(":")
        if url.scheme.startswith("ss"):
            kwargs["cipher"] = ciphers[cipher_name](password)
        elif url.scheme in ("http", "https", "socks"):
            kwargs["auth"] = (cipher_name.encode(), password.encode())
    elif url.scheme in ("ss", "ssudp"):
        raise argparse.ArgumentTypeError(
            f"you need to assign cryto algorithm and password: {uri}"
        )
    if loc:
        host, _, port = loc.partition(":")
        port = int(port)
        bind_addr = (host, port)
    else:
        raise Exception("You must specify a port")
    qs = parse.parse_qs(url.query)
    if url.scheme == "tunneludp":
        if "target" not in qs:
            raise argparse.ArgumentTypeError(
                "destitation must be assign in tunnel udp mode, "
                "example tunneludp://:53/?target=8.8.8.8:53"
            )
        host, _, port = qs["target"].partition(":")
        kwargs["target_addr"] = (host, int(port))
    if "plugin" in qs:
        plugin_info = qs["plugin"][0]
        plugin_name, _, args = plugin_info.partition(";")
        args = [arg for arg in args.split(",") if arg]
        kwargs["plugin"] = plugins[plugin_name](*args)
    if is_via:
        kwargs["bind_addr"] = bind_addr
        return ViaNamespace(ClientClass=proto, **kwargs)
    elif "via" in qs:
        kwargs["via"] = get_server(qs["via"][0], True)
    if url.scheme.endswith("udp"):
        server_sock = udp_server_socket(*bind_addr)
        bind_addr = server_sock._socket.getsockname()
        server = run_udp_server(server_sock, proto(**kwargs))
    else:
        server_sock = curio.tcp_server_socket(*bind_addr, backlog=1024)
        bind_addr = server_sock._socket.getsockname()
        server = run_server(
            server_sock, TcpProtoFactory(proto, **kwargs), ssl=ssl_context
        )
    return server, bind_addr, url.scheme


async def multi_server(*servers):
    addrs = []
    async with curio.TaskGroup() as g:
        for server, addr, scheme in servers:
            await g.spawn(server)
            addrs.append((*addr, scheme))

        # await g.spawn(show_stats())
        address = ", ".join(f"{scheme}://{host}:{port}" for host, port, scheme in addrs)
        ss_filter = " or ".join(f"dport = {port}" for host, port, scheme in addrs)
        pid = os.getpid()
        gvars.logger.info(f"{__package__}/{__version__} listen on {address} pid: {pid}")
        gvars.logger.debug(f"sudo lsof -p {pid} -P | grep -e TCP -e STREAM")
        gvars.logger.debug(f'ss -o "( {ss_filter} )"')


async def udp_server_socket(
    host, port, *, family=socket.AF_INET, reuse_address=True
):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        if reuse_address:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        return sock
    except Exception:
        await sock.close()
        raise


async def run_udp_server(sock, handler_task):
    async with sock:
        await handler_task(sock)


def main():
    parser = argparse.ArgumentParser(
        description=desc, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-v", dest="verbose", action="count", default=0, help="print verbose output"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("server", nargs="+", type=get_server)
    args = parser.parse_args()
    if args.verbose == 0:
        level = logging.ERROR
    elif args.verbose == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    gvars.logger.setLevel(level)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (50000, 50000))
    except Exception as e:
        gvars.logger.warning("Require root permission to allocate resources")
    kernel = curio.Kernel()
    try:
        kernel.run(multi_server(*args.server))
    except Exception as e:
        traceback.print_exc()
        for conn in connections:
            gvars.logger.debug(f"| {conn}")
    except KeyboardInterrupt:
        kernel.run(shutdown=True)


if __name__ == "__main__":
    main()
