from .socks import SocksProxy
from .shadowsocks import SSProxy, SSClient
from .http import HTTPProxy, HTTPClient


server_protos = {"ss": SSProxy, "socks": SocksProxy, "http": HTTPProxy}
via_protos = {"ss": SSClient, "http": HTTPClient}
