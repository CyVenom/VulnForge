import asyncio

import pytest
from aiohttp import web

from core.ticketing import GitHubTicketing, TicketingError, finding_key

T = "app.test"


def f(title, sev="high", **kw):
    return {"title": title, "severity": sev, "category": "c", "source": "s",
            "description": "desc", "remediation": "fix", **kw}


def make(tmp_path, monkeypatch, api_base="http://127.0.0.1:1", **cfg):
    monkeypatch.setenv("GH_TEST_TOKEN", "tok")
    c = {"ticketing": {"enabled": True, "repo": "o/r", "token_env": "GH_TEST_TOKEN", **cfg}}
    return GitHubTicketing(c, api_base=api_base, state_path=str(tmp_path / "state.json"))


def test_key_is_stable_and_target_specific():
    assert finding_key(T, f("A")) == finding_key(T, f("A"))
    assert finding_key(T, f("A")) != finding_key("other.test", f("A"))
    assert finding_key(T, f("A")) != finding_key(T, f("B"))


def test_plan_filters_severity(tmp_path, monkeypatch):
    t = make(tmp_path, monkeypatch, min_severity="high")
    plan = t.plan(T, [f("A", "critical"), f("B", "low")])
    assert [x["title"] for x in plan["create"]] == ["A"]


def test_render_omits_evidence_by_default_and_has_marker(tmp_path, monkeypatch):
    fd = f("A", evidence="secret-host.internal")
    body = make(tmp_path, monkeypatch).render("VF-1", T, fd)
    assert "secret-host.internal" not in body["body"]
    assert f"vulnforge-key:{finding_key(T, fd)}" in body["body"]
    assert "severity:high" in body["labels"]
    body2 = make(tmp_path, monkeypatch, include_evidence=True).render("VF-1", T, fd)
    assert "secret-host.internal" in body2["body"]


def test_dry_run_sends_nothing_and_needs_no_token(tmp_path, monkeypatch):
    t = make(tmp_path, monkeypatch)
    monkeypatch.delenv("GH_TEST_TOKEN")
    t.token = ""
    r = asyncio.run(t.sync("VF-1", T, [f("A")]))
    assert r["applied"] is False and r["would_create"] == ["A"] and not t.state_path.exists()


def test_apply_requires_config_and_token(tmp_path, monkeypatch):
    t = make(tmp_path, monkeypatch)
    t.token = ""
    with pytest.raises(TicketingError):
        asyncio.run(t.sync("VF-1", T, [f("A")], apply=True))
    t2 = GitHubTicketing({}, state_path=str(tmp_path / "s2.json"))
    with pytest.raises(TicketingError):
        asyncio.run(t2.sync("VF-1", T, [f("A")], apply=True))


def test_create_dedupe_and_close(tmp_path, monkeypatch):
    calls = []

    async def create(r):
        calls.append(("create", await r.json(), r.headers.get("Authorization")))
        return web.json_response({"number": 100 + len(calls)}, status=201)

    async def comment(r):
        calls.append(("comment", r.match_info["n"]))
        return web.json_response({}, status=201)

    async def patch(r):
        calls.append(("close", r.match_info["n"], (await r.json())["state"]))
        return web.json_response({}, status=200)

    async def main():
        app = web.Application()
        app.router.add_post("/repos/o/r/issues", create)
        app.router.add_post("/repos/o/r/issues/{n}/comments", comment)
        app.router.add_patch("/repos/o/r/issues/{n}", patch)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        t = make(tmp_path, monkeypatch, api_base=f"http://127.0.0.1:{port}")
        try:
            r1 = await t.sync("VF-1", T, [f("A"), f("B")], apply=True)
            r2 = await t.sync("VF-2", T, [f("A"), f("B")], apply=True)   # nothing new
            r3 = await t.sync("VF-3", T, [f("A")], apply=True)            # B resolved
        finally:
            await runner.cleanup()
        return r1, r2, r3

    r1, r2, r3 = asyncio.run(main())
    assert len(r1["created"]) == 2 and r1["errors"] == []
    assert r2["created"] == [] and r2["existing"] == 2
    assert len(r3["closed"]) == 1 and r3["existing"] == 1
    assert calls[0][2] == "Bearer tok"
    assert [c[0] for c in calls].count("create") == 2
    assert ("close", str(r3["closed"][0]), "closed") in calls


def test_http_failure_recorded_not_raised(tmp_path, monkeypatch):
    async def boom(r):
        return web.json_response({}, status=403)

    async def main():
        app = web.Application()
        app.router.add_post("/repos/o/r/issues", boom)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        t = make(tmp_path, monkeypatch, api_base=f"http://127.0.0.1:{port}")
        try:
            return await t.sync("VF-1", T, [f("A")], apply=True), t
        finally:
            await runner.cleanup()

    r, t = asyncio.run(main())
    assert r["created"] == [] and len(r["errors"]) == 1
    assert t.plan(T, [f("A")])["create"]  # still pending, will retry next time
