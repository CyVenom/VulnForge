"""
VulnForge Authorization Audit Trail
Records every authorization-relevant decision (confirmation prompts,
blocked-range hits, scan start/finish) to a local
SQLite log, independent of scan history, so there's a durable record of
*who was told what and what was decided* for compliance/legal purposes —
not just what the scanner found.
"""
import csv
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("vulnforge.audit")

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    target TEXT,
    scan_id TEXT,
    actor TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target);
CREATE INDEX IF NOT EXISTS idx_audit_scan_id ON audit_log(scan_id);
"""


class AuditTrail:
    """Thin SQLite wrapper for the authorization audit log."""

    def __init__(self, config: dict):
        auth_cfg = config.get("authorization", {})
        audit_cfg = auth_cfg.get("audit", {})
        self.enabled = audit_cfg.get("enabled", True)
        self.db_path = Path(audit_cfg.get("db_path", "reports/audit.db"))
        self.actor = audit_cfg.get("actor") or self._default_actor()
        if self.enabled:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    @staticmethod
    def _default_actor() -> str:
        import getpass
        try:
            return getpass.getuser()
        except Exception:
            return "unknown"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def record(
        self,
        event_type: str,
        target: str | None = None,
        scan_id: str | None = None,
        detail: str | dict | None = None,
    ) -> None:
        """Append one audit entry. Never raises — auditing is best-effort
        and must not block a scan if the audit DB is unavailable."""
        if not self.enabled:
            return
        try:
            detail_str = json.dumps(detail) if isinstance(detail, dict) else (detail or "")
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_log (timestamp, event_type, target, scan_id, actor, detail)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (datetime.now().isoformat(), event_type, target, scan_id, self.actor, detail_str),
                )
            logger.debug(f"Audit: {event_type} target={target} scan_id={scan_id}")
        except Exception as exc:
            logger.error(f"Failed to write audit entry: {exc}", exc_info=True)

    def list_entries(
        self,
        target: str | None = None,
        scan_id: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        if not self.enabled or not self.db_path.exists():
            return []
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if target:
            query += " AND target = ?"
            params.append(target)
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def export(self, out_path: str, fmt: str = "json", target: str | None = None) -> str:
        """Export the full audit trail (optionally filtered by target) to a
        file for compliance hand-off. Returns the written path."""
        entries = self.list_entries(target=target, limit=10_000_000)
        entries.reverse()  # chronological order for export

        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["id", "timestamp", "event_type", "target", "scan_id", "actor", "detail"]
                )
                writer.writeheader()
                writer.writerows(entries)
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2)

        logger.info(f"Audit trail exported to {path} ({len(entries)} entries, format={fmt})")
        return str(path)
