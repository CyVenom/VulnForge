import asyncio

import aiohttp
from aiohttp import web

from core.web_fingerprint import check_cms, check_graphql

WP = ('<html><head><meta name="generator" content="WordPress 4.9.8" />'
      "<link href='/wp-content/x.css'></head></html>")


def make_app():
    async def gql(r):
        q = (await r.json())["query"]
        if "__schema" in q:
            return web.json_response({"data": {"__schema": {"types": [{"name": "Query"}, {"name": "__Type"}]}}})
        return web.json_response({"data": {"__typename": "Query"}})

    async def users(r):
        return web.json_response([{"slug": "admin"}])

    app = web.Application()
    app.router.add_post("/graphql", gql)
    app.router.add_get("/wp-json/wp/v2/users", users)
    return app


async def run(check, body=WP):
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    findings: list = []
    try:
        async with aiohttp.ClientSession() as s:
            await check(s, f"http://127.0.0.1:{port}", findings, {"body_snippet": body, "headers": {}})
    finally:
        await runner.cleanup()
    return [f["title"] for f in findings]


def test_graphql_and_introspection():
    t = asyncio.run(run(lambda s, b, f, r: check_graphql(s, b, f)))
    assert any("Endpoint Discovered: /graphql" in x for x in t)
    assert any("Introspection Enabled" in x for x in t)


def test_wordpress_detection_version_and_users():
    t = asyncio.run(run(lambda s, b, f, r: check_cms(s, b, r, f)))
    assert "CMS Detected: WordPress 4.9.8" in t
    assert any("User Enumeration" in x for x in t)
    assert any("Outdated WordPress" in x for x in t)


def test_plain_site_yields_nothing():
    assert asyncio.run(run(lambda s, b, f, r: check_cms(s, b, r, f), body="<html>hello</html>")) == []
