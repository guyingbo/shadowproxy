from .socks.server import SocksProxy
from .socks.client import SocksClient
from .shadowsocks.server import SSProxy
from .shadowsocks.client import SSClient
from .http.server import HTTPProxy
from .http.client import HTTPClient


server_protos = {"ss": SSProxy, "socks": SocksProxy, "http": HTTPProxy}
via_protos = {"ss": SSClient, "http": HTTPClient, "socks": SocksClient}
