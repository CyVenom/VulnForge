"""
VulnForge Scheduler
Runs configured scans on a recurring interval. The targets listed in a
schedule in config.json are the operator's own authorization for those
scans, so unattended runs skip the interactive prompt. Blocked reserved-IP
ranges are still refused by the scanner.

config.json:
  "schedules": [
    {"name": "weekly-web", "targets": ["app.example.com"], "every": "7d",
     "scan_types": ["ssl", "web"], "profile": "balanced"}
  ]

Last-run times are kept in reports/schedule_state.json. Use
`vulnforge.py schedule run --once` from cron / Windows Task Scheduler, or
`vulnforge.py schedule run` to keep a foreground loop alive.
"""
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("vulnforge.scheduler")

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
MIN_INTERVAL = timedelta(minutes=5)


def parse_interval(text: str) -> timedelta:
    """'30m', '6h', '1d', '2w' -> timedelta. Raises ValueError on junk or < 5 minutes."""
    m = re.fullmatch(r"\s*(\d+)\s*([smhdw])\s*", str(text).lower())
    if not m:
        raise ValueError(f"Bad interval {text!r} (use e.g. 30m, 6h, 1d, 2w)")
    delta = timedelta(seconds=int(m.group(1)) * UNITS[m.group(2)])
    if delta < MIN_INTERVAL:
        raise ValueError(f"Interval {text!r} is below the 5 minute minimum")
    return delta


class Scheduler:
    def __init__(self, config: dict, state_path: str | None = None):
        self.config = config
        self.schedules: list[dict] = config.get("schedules", [])
        reports_dir = config.get("reporting", {}).get("output_dir", "reports")
        self.state_path = Path(state_path or Path(reports_dir) / "schedule_state.json")

    # ---- state ----
    def _load_state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    # ---- planning ----
    def describe(self, now: datetime | None = None) -> list[dict]:
        """One row per schedule: name, targets, interval, last run, next due, problem (if any)."""
        now = now or datetime.now()
        state = self._load_state()
        rows = []
        for s in self.schedules:
            row = {"name": s.get("name", "?"), "targets": s.get("targets", []), "every": s.get("every"),
                   "last_run": state.get(s.get("name", "?")), "next_due": None, "problem": None}
            try:
                interval = parse_interval(s.get("every", ""))
                last = datetime.fromisoformat(row["last_run"]) if row["last_run"] else None
                row["next_due"] = (last + interval if last else now).isoformat(timespec="seconds")
            except ValueError as exc:
                row["problem"] = str(exc)
            if not s.get("name") or not s.get("targets"):
                row["problem"] = row["problem"] or "schedule needs a name and at least one target"
            rows.append(row)
        return rows

    def due(self, now: datetime | None = None) -> list[dict]:
        now = now or datetime.now()
        due = []
        for s, row in zip(self.schedules, self.describe(now)):
            if row["problem"] or not row["next_due"]:
                if row["problem"]:
                    logger.warning(f"Schedule {row['name']!r} skipped: {row['problem']}")
                continue
            if datetime.fromisoformat(row["next_due"]) <= now:
                due.append(s)
        return due

    # ---- execution ----
    async def run_due(self, scanner, now: datetime | None = None) -> list[dict]:
        """
        Run every due schedule with the given VulnForgeScanner. Returns one
        outcome dict per (schedule, target): status is 'completed' or 'error'.
        The schedule's last-run time is only advanced when at least one
        target actually scanned, so a failing schedule retries next tick.
        """
        now = now or datetime.now()
        outcomes: list[dict] = []
        state = self._load_state()

        for sched in self.due(now):
            name = sched["name"]
            ran_any = False
            for target in sched["targets"]:
                scanner.audit.record("scheduled_scan_started", target=target, detail={"schedule": name})
                try:
                    result = await scanner.scan(
                        target=target,
                        scan_types=sched.get("scan_types"),
                        output_formats=sched.get("output", ["json"]),
                        skip_auth_check=True,  # no human present; the schedule is the authorization
                    )
                    ran_any = True
                    outcomes.append({"schedule": name, "target": target, "status": "completed",
                                     "scan_id": result.scan_id, "risk_score": result.summary.get("risk_score", 0)})
                except Exception as exc:
                    logger.error(f"Scheduled scan {name!r}/{target} failed: {exc}", exc_info=True)
                    outcomes.append({"schedule": name, "target": target, "status": "error", "reason": str(exc)})

            if ran_any:
                state[name] = now.isoformat(timespec="seconds")
                self._save_state(state)

        return outcomes
