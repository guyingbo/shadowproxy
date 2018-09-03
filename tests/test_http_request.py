import curio
import subprocess
from shadowproxy import gvars
from shadowproxy.cli import get_server, get_client

gvars.logger.setLevel(10)


async def make_request(client):
    headers = ["User-Agent: curl/7.54.0", "Accept: */*"]
    async with client:
        async with curio.timeout_after(20):
            response = await client.http_request(
                "http://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js", headers=headers
            )
            response.size == 264


async def main(coro, *server_coros):
    async with curio.TaskGroup() as g:
        for server_coro in server_coros:
            await g.spawn(server_coro)
        task = await g.spawn(coro)
        await task.join()
        await g.cancel_remaining()


def test_http():
    server, bind_addr, _ = get_server("http://user:password@127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"http://user:password@{bind_address}")
    curio.run(main(make_request(client), server))


def test_http_only():
    server, bind_addr, _ = get_server("http://user:password@127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"httponly://user:password@{bind_address}")
    curio.run(main(make_request(client), server))


def test_socks5():
    server, bind_addr, _ = get_server("socks://127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"socks://{bind_address}")
    curio.run(main(make_request(client), server))


def test_socks4():
    server, bind_addr, _ = get_server("socks4://127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"socks4://{bind_address}")
    curio.run(main(make_request(client), server))


def test_socks5_with_auth():
    server, bind_addr, _ = get_server("socks://user:password@127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"socks://user:password@{bind_address}")
    curio.run(main(make_request(client), server))


def test_ss():
    server, bind_addr, _ = get_server("ss://aes-256-cfb:123456@127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"ss://aes-256-cfb:123456@{bind_address}")
    curio.run(main(make_request(client), server))


def test_ss_http_simple():
    server, bind_addr, _ = get_server(
        "ss://chacha20:123456@127.0.0.1:0/?plugin=http_simple"
    )
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"ss://chacha20:123456@{bind_address}/?plugin=http_simple")
    curio.run(main(make_request(client), server))


def test_ss_over_tls():
    server, bind_addr, _ = get_server("ss://chacha20:1@127.0.0.1:0/?plugin=tls1.2")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"ss://chacha20:1@{bind_address}/?plugin=tls1.2")
    curio.run(main(make_request(client), server))


def test_aead():
    server, bind_addr, _ = get_server("ss://aes-128-gcm:123456@127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"ss://aes-128-gcm:123456@{bind_address}")
    curio.run(main(make_request(client), server))


def test_transparent():
    server, bind_addr, _ = get_server("red://:12345")

    async def job():
        assert subprocess.run(["curl", "https://1.1.1.1/"]).returncode == 0

    curio.run(main(job, server))


def test_via():
    via_server, bind_addr, _ = get_server("ss://chacha20:1@127.0.0.1:0")
    via_address = f"{bind_addr[0]}:{bind_addr[1]}"
    server, bind_addr, _ = get_server(
        f"socks://127.0.0.1:0/?via=ss://chacha20:1@{via_address}"
    )
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_client(f"socks://{bind_address}")
    curio.run(main(make_request(client), server, via_server))
