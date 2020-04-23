import argparse
import base64
import ipaddress
import logging
import os
import resource
import weakref
from urllib import parse

import curio
from curio import socket, ssl
from curio.network import run_server

from . import __doc__ as desc
from . import __version__, gvars
from .ciphers import ciphers
from .plugins import plugins
from .proxies import server_protos, via_protos
from .utils import ViaNamespace

connections = weakref.WeakSet()


def TcpProtoFactory(cls, **kwargs):
    async def client_handler(client, addr):
        handler = cls(**kwargs)
        connections.add(handler)
        return await handler(client, addr)

    return client_handler


def get_ssl(url):
    ssl_context = None
    if url.scheme in ("https",):
        if not url.fragment:
            raise argparse.ArgumentTypeError("#keyfile,certfile is needed")
        keyfile, _, certfile = url.fragment.partition(",")
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ssl_context


def parse_addr(s):
    host, _, port = s.rpartition(":")
    port = -1 if not port else int(port)
    if not host:
        host = "0.0.0.0"
    elif len(host) >= 4 and host[0] == "[" and host[-1] == "]":
        host = host[1:-1]
    try:
        return (ipaddress.ip_address(host), port)
    except ValueError:
        return (host, port)


def parse_source_ip(qs, kwargs):
    source_ip = qs["source_ip"][0]
    if source_ip in ("in", "same"):
        ip = ipaddress.ip_address(kwargs["bind_addr"][0])
        if not ip.is_loopback:
            source_ip = str(ip)
    return (source_ip, 0)


def get_server(uri, is_via=False):
    url = parse.urlparse(uri)
    kwargs = {}
    proto = via_protos[url.scheme] if is_via else server_protos[url.scheme]
    userinfo, _, loc = url.netloc.rpartition("@")
    if userinfo:
        if ":" not in userinfo:
            userinfo = base64.b64decode(userinfo).decode("ascii")
        cipher_name, _, password = userinfo.partition(":")
        if url.scheme.startswith("ss"):
            kwargs["cipher"] = ciphers[cipher_name](password)
            if not kwargs["cipher"].is_stream_cipher:
                proto = via_protos["aead"] if is_via else server_protos["aead"]
        elif url.scheme in ("http", "https", "socks", "forward"):
            kwargs["auth"] = (cipher_name.encode(), password.encode())
    elif url.scheme in ("ss", "ssudp"):
        raise argparse.ArgumentTypeError(
            f"you need to assign cryto algorithm and password: {uri}"
        )
    host, port = parse_addr(loc)
    if port == -1:
        port = gvars.default_ports.get(url.scheme, gvars.default_port)
    bind_addr = (str(host), port)
    kwargs["bind_addr"] = bind_addr
    if url.path not in ("", "/"):
        kwargs["path"] = url.path
    qs = parse.parse_qs(url.query)
    if url.scheme == "tunneludp":
        if "target" not in qs:
            raise argparse.ArgumentTypeError(
                "destitation must be assign in tunnel udp mode, "
                "example tunneludp://:53/?target=8.8.8.8:53"
            )
        host, port = parse_addr(qs["target"][0])
        kwargs["target_addr"] = (str(host), port)
    if "plugin" in qs:
        plugin_info = qs["plugin"][0]
        plugin_name, _, args = plugin_info.partition(";")
        args = [arg for arg in args.split(",") if arg]
        kwargs["plugin"] = plugins[plugin_name](*args)
    if "source_ip" in qs:
        kwargs["source_addr"] = parse_source_ip(qs, kwargs)
    if is_via:
        kwargs["uri"] = uri
        return ViaNamespace(ClientClass=proto, **kwargs)
    elif "via" in qs:
        kwargs["via"] = get_server(qs["via"][0], True)
    family = socket.AF_INET6 if ":" in bind_addr[0] else socket.AF_INET
    if url.scheme.endswith("udp"):
        server_sock = udp_server_socket(*bind_addr, family=family)
        real_ip, real_port, *_ = server_sock._socket.getsockname()
        server = run_udp_server(server_sock, proto(**kwargs))
    else:
        server_sock = curio.tcp_server_socket(*bind_addr, backlog=1024, family=family)
        real_ip, real_port, *_ = server_sock._socket.getsockname()
        server = run_server(
            server_sock, TcpProtoFactory(proto, **kwargs), ssl=get_ssl(url)
        )
    return server, (real_ip, real_port), url.scheme


def get_client(uri):
    ns = get_server(uri, is_via=True)
    return ns.new()


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


def udp_server_socket(host, port, *, family=socket.AF_INET, reuse_address=True):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if reuse_address:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        sock.bind((host, port))
        return sock
    except Exception:
        sock._socket.close()
        raise


async def run_udp_server(sock, handler_task):
    try:
        async with sock:
            await handler_task(sock)
    except curio.errors.TaskCancelled:
        pass
    except Exception as e:
        gvars.logger.exception(f"error {e}")


def main(arguments=None):
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
    args = parser.parse_args(arguments)
    if args.verbose == 0:
        level = logging.ERROR
    elif args.verbose == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG
    gvars.logger.setLevel(level)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (50000, 50000))
    except Exception:
        gvars.logger.warning("Require root permission to allocate resources")
    kernel = curio.Kernel()
    try:
        kernel.run(multi_server(*args.server))
    except Exception as e:
        gvars.logger.exception(str(e))
    except KeyboardInterrupt:
        kernel.run(shutdown=True)


if __name__ == "__main__":
    main()
