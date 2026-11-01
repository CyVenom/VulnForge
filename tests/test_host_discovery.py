import asyncio

from aiohttp import web

from core.host_discovery import is_alive, sweep


async def _start_server():
    async def ok(r):
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/", ok)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


def test_tcp_alive_detects_open_port():
    async def go():
        runner, port = await _start_server()
        try:
            return await is_alive("127.0.0.1", timeout=1.0, ports=[port])
        finally:
            await runner.cleanup()

    assert asyncio.run(go()) is True


def test_dead_port_on_loopback_is_not_alive():
    # Port 1 is reserved/unassigned and should refuse immediately on loopback;
    # ping to 127.0.0.1 itself usually succeeds, so use a non-loopback
    # documentation-range IP that should neither ping nor accept TCP in CI.
    async def go():
        return await is_alive("192.0.2.1", timeout=0.5, ports=[1])

    assert asyncio.run(go()) is False


def test_sweep_returns_result_per_host():
    async def go():
        runner, port = await _start_server()
        try:
            return await sweep(["127.0.0.1", "192.0.2.1"], timeout=0.5)
        finally:
            await runner.cleanup()

    # Patch COMMON_PROBE_PORTS indirectly isn't needed: 127.0.0.1 has many
    # services during tests, but we only assert the shape/keys here.
    result = asyncio.run(go())
    assert set(result.keys()) == {"127.0.0.1", "192.0.2.1"}
    assert isinstance(result["127.0.0.1"], bool)
