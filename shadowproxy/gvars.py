import logging
import sys

PACKET_SIZE = 8192
logger = logging.getLogger(__package__)
logger.addHandler(logging.StreamHandler(sys.stdout))
default_ports = {"http": 80, "https": 443, "socks": 8527, "forward": 80, "red": 12345}
default_port = 0
