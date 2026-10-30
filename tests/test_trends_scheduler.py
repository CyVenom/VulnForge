import asyncio
import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from core.scheduler import Scheduler, parse_interval
from core.trends import build_trend, direction, sparkline


def scan(sid, risk, titles):
    return {
        "scan_id": sid, "start_time": sid,
        "summary": {"risk_score": risk, "total_findings": len(titles)},
        "findings": [{"title": t, "category": "c", "source": "s", "severity": "medium"} for t in titles],
    }


# ---- trends ----
def test_sparkline_and_direction():
    assert sparkline([]) == ""
    assert len(set(sparkline([5, 5, 5]))) == 1
    assert sparkline([0, 50, 100])[0] == "▁" and sparkline([0, 50, 100])[-1] == "█"
    assert direction([10, 30]) == "worsening"
    assert direction([30, 10]) == "improving"
    assert direction([10, 11]) == "flat"
    assert direction([10]) == "insufficient data"


def test_trend_new_resolved_and_persistence():
    t = build_trend([scan("a", 10, ["x", "y"]), scan("b", 12, ["x", "y"]), scan("c", 20, ["x", "z"])])
    assert [f["title"] for f in t["new_since_previous"]] == ["z"]
    assert [f["title"] for f in t["resolved_since_previous"]] == ["y"]
    ages = {p["title"]: p["scans_present"] for p in t["persistence"]}
    assert ages == {"x": 3, "z": 1}
    assert t["direction"] == "worsening"


def test_trend_single_scan_has_no_deltas():
    t = build_trend([scan("a", 10, ["x"])])
    assert t["new_since_previous"] == [] and t["resolved_since_previous"] == []


def test_persistence_resets_after_gap():
    t = build_trend([scan("a", 1, ["x"]), scan("b", 1, []), scan("c", 1, ["x"])])
    assert t["persistence"][0]["scans_present"] == 1


# ---- interval parsing ----
def test_parse_interval():
    assert parse_interval("6h") == timedelta(hours=6)
    assert parse_interval("2w") == timedelta(weeks=2)
    for bad in ("", "abc", "10", "1m", "0h"):
        with pytest.raises(ValueError):
            parse_interval(bad)


# ---- scheduler ----
class FakeAudit:
    def __init__(self):
        self.events = []

    def record(self, event, **kw):
        self.events.append((event, kw.get("target")))


class FakeScanner:
    def __init__(self):
        self.audit = FakeAudit()
        self.scanned = []

    async def scan(self, target, scan_types=None, output_formats=None, skip_auth_check=False):
        self.scanned.append((target, skip_auth_check))
        return SimpleNamespace(scan_id="VF-T", summary={"risk_score": 7})


def make_sched(tmp_path, targets):
    cfg = {"schedules": [{"name": "s1", "targets": targets, "every": "1h"}]}
    return Scheduler(cfg, state_path=str(tmp_path / "state.json"))


def test_never_run_schedule_is_due_then_waits(tmp_path):
    sch, scanner, now = make_sched(tmp_path, ["a.test"]), FakeScanner(), datetime(2026, 1, 1, 12)
    out = asyncio.run(sch.run_due(scanner, now))
    assert out[0]["status"] == "completed" and scanner.scanned == [("a.test", True)]
    assert ("scheduled_scan_started", "a.test") in scanner.audit.events
    assert asyncio.run(sch.run_due(scanner, now + timedelta(minutes=30))) == []
    assert len(asyncio.run(sch.run_due(scanner, now + timedelta(hours=1, seconds=1)))) == 1


def test_failed_scan_is_reported_and_retried(tmp_path):
    class Boom(FakeScanner):
        async def scan(self, *a, **kw):
            raise ValueError("blocked range")

    sch, scanner = make_sched(tmp_path, ["a.test"]), Boom()
    out = asyncio.run(sch.run_due(scanner, datetime(2026, 1, 1)))
    assert out[0]["status"] == "error" and "blocked range" in out[0]["reason"]
    assert not (tmp_path / "state.json").exists()                      # not marked as run
    assert len(asyncio.run(sch.run_due(scanner, datetime(2026, 1, 1, 0, 1)))) == 1


def test_bad_schedule_is_skipped_not_fatal(tmp_path):
    cfg = {"schedules": [{"name": "bad", "targets": ["a"], "every": "nope"}, {"name": "", "targets": []}]}
    sch = Scheduler(cfg, state_path=str(tmp_path / "s.json"))
    assert sch.due(datetime(2026, 1, 1)) == []
    assert all(r["problem"] for r in sch.describe())
