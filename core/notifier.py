"""
VulnForge Notifier
Sends a short scan-completion summary to Slack, Discord, or a generic JSON
webhook. Opt-in via config.json -> "notifications". Only the headline numbers
and finding titles are sent; evidence, descriptions and raw scan data stay
local. Webhook URLs can come from an environment variable (url_env) so they
don't have to live in config.json. A failing webhook never fails the scan.
"""
import logging
import os
from typing import Any

import aiohttp

logger = logging.getLogger("vulnforge.notifier")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
MAX_TITLES = 5


def _rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index((severity or "info").lower())
    except ValueError:
        return 0


class Notifier:
    def __init__(self, config: dict):
        cfg = config.get("notifications", {})
        self.enabled = cfg.get("enabled", False)
        self.min_severity = cfg.get("min_severity", "high")
        self.timeout = aiohttp.ClientTimeout(total=cfg.get("timeout", 10))
        self.targets: list[dict] = []

        for hook in cfg.get("webhooks", []):
            url = hook.get("url") or os.environ.get(hook.get("url_env", ""), "")
            kind = hook.get("type", "generic").lower()
            if not url:
                logger.warning(f"Webhook {hook.get('name', kind)!r} has no url/url_env value — skipped.")
                continue
            if not url.startswith("https://"):
                logger.warning(f"Webhook {hook.get('name', kind)!r} is not https:// — skipped.")
                continue
            if kind not in ("slack", "discord", "generic"):
                logger.warning(f"Unknown webhook type {kind!r} — skipped.")
                continue
            self.targets.append({"name": hook.get("name", kind), "type": kind, "url": url})

    def build_summary(self, result: Any) -> dict:
        """Reduce a ScanResult to the fields that are safe to leave the machine."""
        summary = result.summary or {}
        threshold = _rank(self.min_severity)
        notable = [f for f in result.findings if _rank(f.get("severity")) >= threshold]
        return {
            "scan_id": result.scan_id,
            "target": result.target,
            "risk_score": summary.get("risk_score", 0),
            "severity_counts": summary.get("severity_counts", {}),
            "total_findings": len(result.findings),
            "notable_count": len(notable),
            "notable_titles": [
                f"[{f.get('severity', 'info').upper()}] {f.get('title', 'N/A')}"
                for f in notable[:MAX_TITLES]
            ],
            "min_severity": self.min_severity,
        }

    @staticmethod
    def format_text(s: dict) -> str:
        lines = [
            f"VulnForge scan {s['scan_id']} finished for {s['target']}",
            f"Risk score: {s['risk_score']}/100 | Findings: {s['total_findings']} "
            f"({s['notable_count']} at {s['min_severity']}+)",
        ]
        lines += [f"- {t}" for t in s["notable_titles"]]
        extra = s["notable_count"] - len(s["notable_titles"])
        if extra > 0:
            lines.append(f"...and {extra} more")
        return "\n".join(lines)

    def _payload(self, kind: str, s: dict) -> dict:
        if kind == "slack":
            return {"text": self.format_text(s)}
        if kind == "discord":
            return {"content": self.format_text(s)[:1900]}
        return s

    async def notify_scan_complete(self, result: Any) -> list[tuple[str, bool]]:
        """POST the summary to every configured webhook. Returns (name, ok) pairs."""
        if not self.enabled or not self.targets:
            return []

        summary = self.build_summary(result)
        # Stay quiet when nothing reached the configured severity.
        if summary["notable_count"] == 0:
            logger.info(f"No findings at {self.min_severity}+ for {result.scan_id} — no notification sent.")
            return []

        outcomes: list[tuple[str, bool]] = []
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for hook in self.targets:
                try:
                    async with session.post(hook["url"], json=self._payload(hook["type"], summary)) as resp:
                        ok = resp.status < 300
                        if not ok:
                            logger.warning(f"Webhook {hook['name']!r} returned HTTP {resp.status}")
                except Exception as exc:
                    # Never log the URL: it often embeds the secret token.
                    logger.warning(f"Webhook {hook['name']!r} failed: {type(exc).__name__}")
                    ok = False
                outcomes.append((hook["name"], ok))
        return outcomes
