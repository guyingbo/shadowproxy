from .http_simple import HttpSimplePlugin
from .tls1_2 import TLS1_2Plugin

plugins = {
    "http_simple": HttpSimplePlugin,
    "tls1.2_ticket_auth": TLS1_2Plugin,
    "tls1.2": TLS1_2Plugin,
}
