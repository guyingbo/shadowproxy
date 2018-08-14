import sys
import logging

PACKET_SIZE = 8192
logger = logging.getLogger(__package__)
logger.addHandler(logging.StreamHandler(sys.stdout))
