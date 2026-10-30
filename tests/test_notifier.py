import asyncio
from types import SimpleNamespace

from core.notifier import Notifier


def result(findings):
    return SimpleNamespace(
        scan_id="VF-1", target="t.test", findings=findings,
        summary={"risk_score": 55, "severity_counts": {"high": 1}},
    )


def cfg(url="https://hooks.test/x", **kw):
    return {"notifications": {"enabled": True, "webhooks": [{"name": "h", "type": "slack", "url": url}], **kw}}


def test_http_and_missing_url_hooks_rejected(monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    assert Notifier(cfg(url="http://insecure.test/x")).targets == []
    c = {"notifications": {"enabled": True, "webhooks": [{"type": "slack", "url_env": "NOPE"}]}}
    assert Notifier(c).targets == []


def test_url_from_env(monkeypatch):
    monkeypatch.setenv("HOOK", "https://hooks.test/secret")
    c = {"notifications": {"enabled": True, "webhooks": [{"type": "discord", "url_env": "HOOK"}]}}
    assert Notifier(c).targets[0]["url"] == "https://hooks.test/secret"


def test_summary_filters_by_severity_and_omits_evidence():
    n = Notifier(cfg(min_severity="high"))
    s = n.build_summary(result([
        {"severity": "critical", "title": "A", "evidence": "SECRET"},
        {"severity": "low", "title": "B"},
    ]))
    assert s["notable_count"] == 1 and s["total_findings"] == 2
    assert s["notable_titles"] == ["[CRITICAL] A"]
    assert "SECRET" not in n.format_text(s)


def test_payload_shapes():
    n = Notifier(cfg())
    s = n.build_summary(result([{"severity": "high", "title": "A"}]))
    assert "text" in n._payload("slack", s)
    assert "content" in n._payload("discord", s)
    assert n._payload("generic", s)["scan_id"] == "VF-1"


def test_no_notification_when_nothing_notable():
    n = Notifier(cfg())
    assert asyncio.run(n.notify_scan_complete(result([{"severity": "low", "title": "B"}]))) == []


def test_delivery_failure_is_reported_not_raised():
    n = Notifier(cfg(url="https://127.0.0.1:1/x", timeout=1))
    out = asyncio.run(n.notify_scan_complete(result([{"severity": "high", "title": "A"}])))
    assert out == [("h", False)]
