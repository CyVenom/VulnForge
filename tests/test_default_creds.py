import asyncio
import base64

from aiohttp import web

from core.default_creds import DefaultCredentialChecker


def make_app(valid_user="admin", valid_pass="admin"):
    async def protected(r):
        auth = r.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            decoded = base64.b64decode(auth[6:]).decode()
            if decoded == f"{valid_user}:{valid_pass}":
                return web.Response(text="welcome")
        return web.Response(text="auth required", status=401, headers={"WWW-Authenticate": 'Basic realm="x"'})

    app = web.Application()
    app.router.add_get("/", protected)
    return app


async def run(config, valid_user="admin", valid_pass="admin", cli_allowed=True):
    app = make_app(valid_user, valid_pass)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}/"
    checker = DefaultCredentialChecker(config)
    try:
        return await checker.check("127.0.0.1", base_url, open_ports={80}, cli_allowed=cli_allowed)
    finally:
        await runner.cleanup()


def test_default_http_basic_credentials_detected():
    config = {"credentials": {"enabled": True, "http_basic_pairs": [["admin", "wrong"], ["admin", "admin"]]}}
    findings = asyncio.run(run(config))
    assert any(f["category"] == "default_credentials" and f["confidence"] == "confirmed" for f in findings)


def test_requires_both_config_and_cli_flag():
    config = {"credentials": {"enabled": True, "http_basic_pairs": [["admin", "admin"]]}}
    # config says enabled, but the per-run CLI flag was not passed.
    findings = asyncio.run(run(config, cli_allowed=False))
    assert findings == []


def test_no_match_in_pair_list_yields_nothing():
    config = {"credentials": {"enabled": True, "http_basic_pairs": [["admin", "wrong1"], ["admin", "wrong2"]]}}
    findings = asyncio.run(run(config))
    assert findings == []


def test_disabled_in_config_yields_nothing():
    config = {"credentials": {"enabled": False}}
    findings = asyncio.run(run(config))
    assert findings == []
