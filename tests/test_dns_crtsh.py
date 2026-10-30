import asyncio

from aiohttp import web

import plugins.plugin_dns as pd


def test_crtsh_parsing_dedup_and_wildcards(monkeypatch):
    async def crt(r):
        return web.json_response([
            {"name_value": "dev.zone.test\n*.zone.test"},
            {"name_value": "dev.zone.test"},
            {"name_value": "other.org"},
        ])

    async def main():
        app = web.Application()
        app.router.add_get("/", crt)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        monkeypatch.setattr(pd, "CRTSH_URL", f"http://127.0.0.1:{port}/?q=%25.{{domain}}")
        data, findings = {"subdomains": {}}, []
        await pd.DNSReconPlugin({})._crtsh_enumeration("zone.test", data, findings, asyncio.get_running_loop())
        await runner.cleanup()
        return data, findings

    data, findings = asyncio.run(main())
    assert data["crtsh_subdomains"] == ["dev.zone.test"]
    assert findings[0]["category"] == "dns"


def test_is_ip_or_local():
    f = pd.DNSReconPlugin._is_ip_or_local
    assert f("10.0.0.1") and f("localhost") and f("box.local")
    assert not f("example.com")
