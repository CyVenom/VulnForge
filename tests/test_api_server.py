import asyncio
import json
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer

from core.api_server import ApiConfigError, check_bind, create_app, load_token

TOKEN = "t" * 24
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class FakeAudit:
    def __init__(self):
        self.events = []

    def record(self, event, **kw):
        self.events.append((event, kw.get("target")))


class FakeScanner:
    def __init__(self, delay=0.0):
        self.audit, self.delay, self.calls = FakeAudit(), delay, []

    async def scan(self, target, scan_types=None, output_formats=None, skip_auth_check=False):
        self.calls.append((target, scan_types, skip_auth_check))
        await asyncio.sleep(self.delay)
        return SimpleNamespace(scan_id="VF-API", summary={"risk_score": 9})


def cfg(tmp_path):
    return {"history": {"enabled": True, "db_path": str(tmp_path / "h.db")}}


async def client(tmp_path, scanner, **kw):
    c = TestClient(TestServer(create_app(cfg(tmp_path), scanner, TOKEN, **kw)))
    await c.start_server()
    return c


def run(coro):
    return asyncio.run(coro)


# ---- startup config ----
def test_token_and_bind_rules():
    with pytest.raises(ApiConfigError):
        load_token({})
    with pytest.raises(ApiConfigError):
        load_token({"VULNFORGE_API_TOKEN": "short"})
    assert load_token({"VULNFORGE_API_TOKEN": TOKEN}) == TOKEN
    check_bind("127.0.0.1", False)
    with pytest.raises(ApiConfigError):
        check_bind("0.0.0.0", False)
    check_bind("0.0.0.0", True)


# ---- auth ----
def test_auth_required_except_health(tmp_path):
    async def main():
        c = await client(tmp_path, FakeScanner())
        try:
            assert (await c.get("/health")).status == 200
            assert (await c.get("/scans")).status == 401
            assert (await c.get("/scans", headers={"Authorization": "Bearer wrong"})).status == 401
            assert (await c.get("/scans", headers={"Authorization": TOKEN})).status == 401
            assert (await c.get("/scans", headers=AUTH)).status == 200
        finally:
            await c.close()
    run(main())


# ---- scan requests ----
def test_scan_validation(tmp_path):
    async def main():
        c = await client(tmp_path, FakeScanner())
        try:
            for body in ({}, {"target": "bad target!"}, {"target": 5}, {"target": "in.test", "scan_types": ["rm -rf"]},
                         {"target": "in.test", "scan_types": "web"}, []):
                assert (await c.post("/scans", json=body, headers=AUTH)).status == 400, body
            r = await c.post("/scans", data="not json", headers=AUTH)
            assert r.status == 400
            big = await c.post("/scans", data="x" * 20000, headers=AUTH)
            assert big.status == 413
        finally:
            await c.close()
    run(main())


def test_scan_job_lifecycle(tmp_path):
    async def main():
        scanner = FakeScanner()
        c = await client(tmp_path, scanner)
        try:
            r = await c.post("/scans", json={"target": "in.test", "scan_types": ["web"]}, headers=AUTH)
            assert r.status == 202
            job = await r.json()
            for _ in range(50):
                j = await (await c.get(f"/jobs/{job['job_id']}", headers=AUTH)).json()
                if j["status"] == "completed":
                    break
                await asyncio.sleep(0.02)
            assert j["status"] == "completed" and j["scan_id"] == "VF-API"
            assert scanner.calls == [("in.test", ["web"], True)]
            assert ("api_scan_started", "in.test") in scanner.audit.events
            assert (await c.get("/jobs/nope", headers=AUTH)).status == 404
        finally:
            await c.close()
    run(main())


def test_one_scan_per_target_and_concurrency_cap(tmp_path):
    async def main():
        c = await client(tmp_path, FakeScanner(delay=0.3), max_concurrent=1)
        try:
            assert (await c.post("/scans", json={"target": "a.test"}, headers=AUTH)).status == 202
            assert (await c.post("/scans", json={"target": "a.test"}, headers=AUTH)).status == 409
            assert (await c.post("/scans", json={"target": "b.test"}, headers=AUTH)).status == 429
        finally:
            await c.close()
    run(main())


def test_read_endpoints_404_and_bad_limit(tmp_path):
    async def main():
        c = await client(tmp_path, FakeScanner())
        try:
            assert (await c.get("/scans/VF-none", headers=AUTH)).status == 404
            assert (await c.get("/targets/none.test/trend", headers=AUTH)).status == 404
            assert (await c.get("/scans?limit=abc", headers=AUTH)).status == 400
        finally:
            await c.close()
    run(main())
