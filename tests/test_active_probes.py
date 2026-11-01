import asyncio

import aiohttp
from aiohttp import web

from core.active_probes import ActiveProbes


def make_app():
    async def reflect(r):
        q = r.query.get("q", "")
        return web.Response(text=f"<html><body>results for: {q}</body></html>", content_type="text/html")

    async def sqlish(r):
        q = r.query.get("id", "")
        if "'" in q:
            return web.Response(text="You have an error in your SQL syntax near ''probe' at line 1", status=500)
        if "1'='1" in q:
            return web.Response(text="<html>" + "row " * 50 + "</html>")
        if "1'='2" in q:
            return web.Response(text="<html>no rows</html>")
        return web.Response(text="<html>baseline</html>")

    async def cmdi(r):
        payload = r.query.get("cmd", "")
        if payload.startswith(";echo "):
            token = payload.split(" ", 1)[1]
            return web.Response(text=f"output: {token}\n")
        return web.Response(text="output: (nothing)")

    app = web.Application()
    app.router.add_get("/reflect", reflect)
    app.router.add_get("/search", sqlish)
    app.router.add_get("/run", cmdi)
    return app


async def run(path: str, config: dict | None = None):
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    findings: list = []
    probes = ActiveProbes(config or {"web": {"active_probes": {"enabled": True, "params": ["q", "id", "cmd"], "max_params": 3}}})
    try:
        async with aiohttp.ClientSession() as s:
            await probes.run(s, f"http://127.0.0.1:{port}{path}", findings)
    finally:
        await runner.cleanup()
    return findings


def test_reflected_xss_detected():
    findings = asyncio.run(run("/reflect"))
    assert any(f["category"] == "xss" for f in findings)


def test_sql_error_detected():
    findings = asyncio.run(run("/search"))
    assert any(f["category"] == "sqli" and f["confidence"] == "high" for f in findings)


def test_command_injection_detected():
    findings = asyncio.run(run("/run"))
    assert any(f["category"] == "command_injection" for f in findings)


def test_disabled_by_config_runs_nothing():
    findings = asyncio.run(run("/reflect", config={"web": {"active_probes": {"enabled": False}}}))
    assert findings == []
