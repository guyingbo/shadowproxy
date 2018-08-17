from .socks import SocksProxy
from .shadowsocks import SSProxy, SSClient
from .http.server import HTTPProxy
from .http.client import HTTPClient


server_protos = {"ss": SSProxy, "socks": SocksProxy, "http": HTTPProxy}
via_protos = {"ss": SSClient, "http": HTTPClient}
