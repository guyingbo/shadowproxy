from .socks import SocksProxy
from .shadowsocks import SSProxy, SSClient


server_protos = {"ss": SSProxy, "socks": SocksProxy}
via_protos = {"ss": SSClient}
