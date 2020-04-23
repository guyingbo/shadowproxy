from .aead.client import AEADClient
from .aead.server import AEADProxy
from .http.client import HTTPClient, HTTPForwardClient
from .http.server import HTTPProxy
from .shadowsocks.client import SSClient
from .shadowsocks.server import SSProxy
from .shadowsocks.udpclient import SSUDPClient
from .shadowsocks.udpserver import SSUDPServer
from .socks.client import Socks4Client, SocksClient
from .socks.server import Socks4Proxy, SocksProxy
from .transparent.server import TransparentProxy
from .tunnel.udpserver import TunnelUDPServer

server_protos = {
    "ss": SSProxy,
    "aead": AEADProxy,
    "socks": SocksProxy,
    "http": HTTPProxy,
    "red": TransparentProxy,
    "socks4": Socks4Proxy,
    "tunneludp": TunnelUDPServer,
    "ssudp": SSUDPServer,
}
via_protos = {
    "ss": SSClient,
    "aead": AEADClient,
    "http": HTTPClient,
    "forward": HTTPForwardClient,
    "socks": SocksClient,
    "socks4": Socks4Client,
    "ssudp": SSUDPClient,
}
