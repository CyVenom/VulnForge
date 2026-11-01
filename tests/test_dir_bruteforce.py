import asyncio

import aiohttp
from aiohttp import web

from core.dir_bruteforce import DirBruteforce


def make_app():
    async def admin(r):
        return web.Response(text="<html>" + "admin panel content " * 20 + "</html>", status=200)

    async def listing(r):
        return web.Response(text="<html><title>Index of /uploads</title>" + "x" * 200 + "</html>", status=200)

    async def restricted(r):
        return web.Response(text="forbidden", status=403)

    async def catch_all(r):
        # Everything else answers 200 with the same short body -- a soft-404 SPA router.
        return web.Response(text="nf", status=200)

    app = web.Application()
    app.router.add_get("/admin", admin)
    app.router.add_get("/uploads", listing)
    app.router.add_get("/config", restricted)
    app.router.add_route("*", "/{tail:.*}", catch_all)
    return app


async def run(wordlist_path):
    runner = web.AppRunner(make_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    findings: list = []
    brute = DirBruteforce({"web": {"dir_bruteforce": {"enabled": True, "wordlist_path": str(wordlist_path), "max_concurrency": 5}}})
    try:
        async with aiohttp.ClientSession() as s:
            await brute.run(s, f"http://127.0.0.1:{port}", findings)
    finally:
        await runner.cleanup()
    return findings


def test_real_paths_found_and_catch_all_filtered(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nuploads\nconfig\ndoes-not-exist-at-all\n", encoding="utf-8")

    findings = asyncio.run(run(wordlist))
    titles = {f["title"]: f for f in findings}

    assert any("admin" in t for t in titles)
    assert any("uploads" in t and f["severity"] == "medium" for t, f in titles.items())
    assert any("config" in t and f["severity"] == "info" for t, f in titles.items())
    assert not any("does-not-exist-at-all" in t for t in titles)


def test_disabled_runs_nothing(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    async def run_disabled():
        runner = web.AppRunner(make_app())
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        findings: list = []
        brute = DirBruteforce({"web": {"dir_bruteforce": {"enabled": False, "wordlist_path": str(wordlist)}}})
        try:
            async with aiohttp.ClientSession() as s:
                await brute.run(s, f"http://127.0.0.1:{port}", findings)
        finally:
            await runner.cleanup()
        return findings

    assert asyncio.run(run_disabled()) == []
