import curio
from curio import subprocess

from shadowproxy import gvars
from shadowproxy.__main__ import get_server

gvars.logger.setLevel(10)


async def make_request(bind_addr):
    async with curio.timeout_after(60):
        r = await subprocess.run(
            ["dig", "+short", f"@{bind_addr[0]}", "-p", f"{bind_addr[1]}", "baidu.com"]
        )
        assert r.returncode == 0


async def main(bind_addr, *server_coros):
    async with curio.TaskGroup() as g:
        for server_coro in server_coros:
            await g.spawn(server_coro)
        task = await g.spawn(make_request, bind_addr)
        await task.join()
        await g.cancel_remaining()


def test_tunneludp():
    server, bind_addr, _ = get_server(
        "tunneludp://127.0.0.1:0?target=1.1.1.1:53&source_ip=in"
    )
    curio.run(main(bind_addr, server))


def test_ssudp():
    server, bind_addr, _ = get_server("ssudp://chacha20:1@127.0.0.1:0")
    address = f"{bind_addr[0]}:{bind_addr[1]}"
    server2, bind_addr2, _ = get_server(
        f"tunneludp://127.0.0.1:0/?target=1.1.1.1:53&via=ssudp://chacha20:1@{address}"
    )
    curio.run(main(bind_addr2, server, server2))
