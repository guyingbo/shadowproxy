from .socks.server import SocksProxy, Socks4Proxy
from .socks.client import SocksClient, Socks4Client
from .shadowsocks.server import SSProxy
from .shadowsocks.client import SSClient
from .http.server import HTTPProxy
from .http.client import HTTPClient, HTTPForwardClient
from .transparent.server import TransparentProxy
from .aead.server import AEADProxy
from .aead.client import AEADClient
from .tunnel.udpserver import TunnelUDPServer
from .shadowsocks.udpserver import SSUDPServer
from .shadowsocks.udpclient import SSUDPClient


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
