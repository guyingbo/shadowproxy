from .socks.server import SocksProxy, Socks4Proxy
from .socks.client import SocksClient, Socks4Client
from .shadowsocks.server import SSProxy
from .shadowsocks.client import SSClient
from .http.server import HTTPProxy
from .http.client import HTTPClient, HTTPOnlyClient
from .transparent import TransparentProxy
from .aead.server import AEADProxy
from .aead.client import AEADClient


server_protos = {
    "ss": SSProxy,
    "aead": AEADProxy,
    "socks": SocksProxy,
    "http": HTTPProxy,
    "red": TransparentProxy,
    "socks4": Socks4Proxy,
}
via_protos = {
    "ss": SSClient,
    "aead": AEADClient,
    "http": HTTPClient,
    "httponly": HTTPOnlyClient,
    "socks": SocksClient,
    "socks4": Socks4Client,
}
