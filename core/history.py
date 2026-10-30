"""
VulnForge Scan History
Persists a summary + full result snapshot of every scan to a local SQLite
database so results can be listed and diffed over time.
"""
import json
import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import ScanResult

logger = logging.getLogger("vulnforge.history")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    duration REAL,
    risk_score INTEGER,
    total_findings INTEGER,
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
"""


class ScanHistory:
    """Thin SQLite wrapper for recording and querying past scans."""

    def __init__(self, config: dict):
        history_cfg = config.get("history", {})
        self.enabled = history_cfg.get("enabled", True)
        self.db_path = Path(history_cfg.get("db_path", "reports/history.db"))
        if self.enabled:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def record(self, result: "ScanResult") -> None:
        """Store a completed scan. Never raises — history is best-effort."""
        if not self.enabled:
            return
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scans
                        (scan_id, target, start_time, end_time, duration,
                         risk_score, total_findings, result_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scan_id,
                        result.target,
                        result.start_time,
                        result.end_time,
                        result.duration,
                        result.summary.get("risk_score", 0),
                        result.summary.get("total_findings", 0),
                        json.dumps(result.to_dict(), default=str),
                    ),
                )
            logger.info(f"Scan {result.scan_id} recorded to history ({self.db_path})")
        except Exception as exc:
            logger.error(f"Failed to record scan history: {exc}", exc_info=True)

    def list_scans(self, target: str | None = None, limit: int = 20) -> list[dict]:
        if not self.enabled or not self.db_path.exists():
            return []
        with self._connect() as conn:
            if target:
                rows = conn.execute(
                    "SELECT scan_id, target, start_time, duration, risk_score, total_findings "
                    "FROM scans WHERE target = ? ORDER BY start_time DESC LIMIT ?",
                    (target, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT scan_id, target, start_time, duration, risk_score, total_findings "
                    "FROM scans ORDER BY start_time DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_result(self, scan_id: str) -> dict | None:
        if not self.enabled or not self.db_path.exists():
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def list_results(self, target: str, limit: int = 10) -> list[dict]:
        """Full parsed results for a target's most recent scans, oldest first."""
        if not self.enabled or not self.db_path.exists():
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT result_json FROM scans WHERE target = ? ORDER BY start_time DESC LIMIT ?",
                (target, limit),
            ).fetchall()
        return [json.loads(r["result_json"]) for r in reversed(rows)]

    @staticmethod
    def diff(old: dict, new: dict) -> dict:
        """
        Compare two stored scan results (as dicts) by finding title+category.
        Returns {"new": [...], "resolved": [...], "unchanged": [...]}.
        """
        def _key(f: dict) -> tuple:
            return (f.get("title", ""), f.get("category", ""), f.get("source", ""))

        old_findings = {_key(f): f for f in old.get("findings", [])}
        new_findings = {_key(f): f for f in new.get("findings", [])}

        old_keys, new_keys = set(old_findings), set(new_findings)

        return {
            "new": [new_findings[k] for k in sorted(new_keys - old_keys, key=str)],
            "resolved": [old_findings[k] for k in sorted(old_keys - new_keys, key=str)],
            "unchanged": [new_findings[k] for k in sorted(new_keys & old_keys, key=str)],
        }
