"""
VulnForge Trends
Pure functions that turn a target's scan history into a risk trend and a
finding-persistence report. No I/O of their own: they take the parsed
result dicts that ScanHistory.list_results() returns (oldest first).
"""
from typing import Any

SPARK = "▁▂▃▄▅▆▇█"
SEVERITIES = ("critical", "high", "medium", "low", "info")


def finding_key(f: dict) -> tuple:
    """Same identity ScanHistory.diff() uses, so trend and diff agree."""
    return (f.get("title", ""), f.get("category", ""), f.get("source", ""))


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    if hi == lo:
        return SPARK[0] * len(values)
    step = (hi - lo) / (len(SPARK) - 1)
    return "".join(SPARK[round((v - lo) / step)] for v in values)


def direction(scores: list[int], tolerance: int = 3) -> str:
    """'improving' / 'worsening' / 'flat' comparing the newest scan to the previous one."""
    if len(scores) < 2:
        return "insufficient data"
    delta = scores[-1] - scores[-2]
    if delta > tolerance:
        return "worsening"
    if delta < -tolerance:
        return "improving"
    return "flat"


def build_trend(results: list[dict[str, Any]]) -> dict:
    """
    results: parsed scan dicts, oldest first.
    Returns points, direction, and for the latest scan how many consecutive
    scans (including it) each finding has been present.
    """
    points = []
    for r in results:
        summary = r.get("summary", {})
        points.append({
            "scan_id": r.get("scan_id"),
            "start_time": r.get("start_time"),
            "risk_score": summary.get("risk_score", 0),
            "total_findings": summary.get("total_findings", len(r.get("findings", []))),
            "severity_counts": summary.get("severity_counts", {}),
        })

    scores = [p["risk_score"] for p in points]

    persistence: list[dict] = []
    new_findings: list[dict] = []
    resolved_findings: list[dict] = []
    if results:
        latest = results[-1].get("findings", [])
        previous_keys = {finding_key(f) for f in results[-2].get("findings", [])} if len(results) > 1 else None
        for f in latest:
            age = 0
            for r in reversed(results):
                if finding_key(f) in {finding_key(x) for x in r.get("findings", [])}:
                    age += 1
                else:
                    break
            persistence.append({"title": f.get("title"), "severity": f.get("severity", "info"), "scans_present": age})
            if previous_keys is not None and finding_key(f) not in previous_keys:
                new_findings.append(f)
        if len(results) > 1:
            latest_keys = {finding_key(f) for f in latest}
            resolved_findings = [f for f in results[-2].get("findings", []) if finding_key(f) not in latest_keys]

    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    persistence.sort(key=lambda p: (sev_rank.get(p["severity"], 9), -p["scans_present"]))

    return {
        "points": points,
        "sparkline": sparkline(scores),
        "direction": direction(scores),
        "persistence": persistence,
        "new_since_previous": new_findings,
        "resolved_since_previous": resolved_findings,
    }
