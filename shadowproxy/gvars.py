import sys
import logging

PACKET_SIZE = 8192
logger = logging.getLogger(__package__)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
default_ports = {"http": 80, "https": 443, "socks": 8527, "httponly": 80, "red": 12345}
default_port = 0
