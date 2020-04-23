import argparse
import os
import signal

import pytest

from shadowproxy.__main__ import get_server, main


def test_cli():
    with pytest.raises(argparse.ArgumentTypeError):
        get_server("ss://")


def test_main():
    def handler(*args):
        os.kill(os.getpid(), signal.SIGINT)

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(3)
    main(["-v", "ss://chacha20:1@:0"])
