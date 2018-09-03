import os
import signal
import pytest
import argparse
from shadowproxy.cli import get_server, get_client, main


def test_cli():
    with pytest.raises(argparse.ArgumentTypeError):
        get_server("ss://")


def test_get_client():
    ns = get_client("shadowproxy.proxies.socks.client.SocksClient://:0")
    assert "SocksClient" == ns.__class__.__name__


def test_main():
    def handler(*args):
        os.kill(os.getpid(), signal.SIGINT)

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(3)
    main(["-v", "ss://chacha20:1@:0"])
