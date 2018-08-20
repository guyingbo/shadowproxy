import curio
from shadowproxy.cli import get_server


async def make_request(client):
    headers = ["User-Agent: curl/7.54.0", "Accept: */*"]
    async with client:
        async with curio.timeout_after(60):
            response = await client.http_request(
                "http://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js", headers=headers
            )
            response.size == 264


async def main(server_coro, client):
    async with curio.TaskGroup() as g:
        await g.spawn(server_coro)
        task = await g.spawn(make_request, client)
        await task.join()
        await g.cancel_remaining()


def test_http():
    server, bind_addr, _ = get_server("http://127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_server(f"http://{bind_address}", is_via=True).new()
    curio.run(main(server, client))


def test_http_only():
    server, bind_addr, _ = get_server("http://127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_server(f"httponly://{bind_address}", is_via=True).new()
    curio.run(main(server, client))


def test_sock5():
    server, bind_addr, _ = get_server("socks://127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_server(f"socks://{bind_address}", is_via=True).new()
    curio.run(main(server, client))


def test_ss():
    server, bind_addr, _ = get_server("ss://aes-256-cfb:123456@127.0.0.1:0")
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_server(f"ss://aes-256-cfb:123456@{bind_address}", is_via=True).new()
    curio.run(main(server, client))


def test_ss_http_simple():
    server, bind_addr, _ = get_server(
        "ss://chacha20:123456@127.0.0.1:0/?plugin=http_simple"
    )
    bind_address = f"{bind_addr[0]}:{bind_addr[1]}"
    client = get_server(
        f"ss://chacha20:123456@{bind_address}/?plugin=http_simple", is_via=True
    ).new()
    curio.run(main(server, client))
