"""
VulnForge Ticketing (GitHub Issues)
Turns a recorded scan's findings into GitHub issues, one per distinct
finding, and closes issues whose finding is no longer detected.

Safety:
  * Dry run unless the caller passes apply=True (CLI: --apply). Creating an
    issue publishes text to GitHub, possibly to a public repo, so nothing is
    sent by surprise.
  * Evidence is left out of issue bodies unless ticketing.include_evidence is
    true; evidence often contains hostnames, paths and usernames.
  * The token comes from an environment variable (token_env), never config.
  * Dedup: each finding gets a stable key (target + title + category +
    source). Keys map to issue numbers in reports/ticket_state.json, and the
    key is also embedded in the issue body as a marker.

config.json:
  "ticketing": {"enabled": true, "repo": "owner/name", "token_env": "GITHUB_TOKEN",
                "min_severity": "high", "labels": ["vulnforge"],
                "include_evidence": false}
"""
import hashlib
import json
import logging
import os
from pathlib import Path

import aiohttp

from .notifier import SEVERITY_ORDER, _rank

logger = logging.getLogger("vulnforge.ticketing")

API_BASE = "https://api.github.com"
MARKER = "<!-- vulnforge-key:{key} -->"


def finding_key(target: str, f: dict) -> str:
    raw = "|".join([target, f.get("title", ""), f.get("category", ""), f.get("source", "")])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class TicketingError(Exception):
    pass


class GitHubTicketing:
    def __init__(self, config: dict, api_base: str = API_BASE, state_path: str | None = None):
        cfg = config.get("ticketing", {})
        self.enabled = cfg.get("enabled", False)
        self.repo = cfg.get("repo", "")
        self.token = os.environ.get(cfg.get("token_env", "GITHUB_TOKEN"), "")
        self.min_severity = cfg.get("min_severity", "high")
        self.labels = list(cfg.get("labels", ["vulnforge"]))
        self.include_evidence = cfg.get("include_evidence", False)
        self.api_base = api_base.rstrip("/")
        reports = config.get("reporting", {}).get("output_dir", "reports")
        self.state_path = Path(state_path or Path(reports) / "ticket_state.json")

    # ---- state: {target: {key: issue_number}} ----
    def _load(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    # ---- planning (pure, no network) ----
    def plan(self, target: str, findings: list[dict]) -> dict:
        """Return {"create": [finding...], "close": [(key, issue_number)...], "existing": n}."""
        threshold = _rank(self.min_severity)
        state = self._load().get(target, {})
        current = {finding_key(target, f): f for f in findings if _rank(f.get("severity")) >= threshold}
        create = [f for k, f in current.items() if k not in state]
        close = [(k, n) for k, n in state.items() if k not in current]
        return {"create": create, "close": close, "existing": len(set(current) & set(state))}

    def render(self, scan_id: str, target: str, f: dict) -> dict:
        sev = f.get("severity", "info")
        body = [
            MARKER.format(key=finding_key(target, f)),
            f"**Severity:** {sev.upper()}",
            f"**Target:** `{target}`",
            f"**First seen in scan:** `{scan_id}`",
            "",
            f.get("description", ""),
            "",
            "### Remediation",
            f.get("remediation", "See scan report."),
        ]
        if self.include_evidence and f.get("evidence"):
            body += ["", "### Evidence", f"```\n{f['evidence']}\n```"]
        body += ["", "_Opened automatically by VulnForge. Verify manually before acting; automated findings can be false positives._"]
        return {
            "title": f"[VulnForge][{sev.upper()}] {f.get('title', 'Finding')} on {target}"[:250],
            "body": "\n".join(body),
            "labels": self.labels + [f"severity:{sev}"],
        }

    # ---- execution ----
    async def sync(self, scan_id: str, target: str, findings: list[dict], apply: bool = False) -> dict:
        plan = self.plan(target, findings)
        report = {"applied": apply, "would_create": [f["title"] for f in plan["create"]],
                  "would_close": [n for _, n in plan["close"]], "existing": plan["existing"],
                  "created": [], "closed": [], "errors": []}
        if not apply:
            return report

        if not self.enabled or not self.repo:
            raise TicketingError("ticketing is not enabled/configured (ticketing.enabled and ticketing.repo)")
        if not self.token:
            raise TicketingError("no GitHub token found in the environment variable named by ticketing.token_env")

        state = self._load()
        tstate = state.setdefault(target, {})
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "VulnForge"}
        base = f"{self.api_base}/repos/{self.repo}/issues"

        async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as session:
            for f in plan["create"]:
                try:
                    async with session.post(base, json=self.render(scan_id, target, f)) as resp:
                        if resp.status != 201:
                            raise TicketingError(f"HTTP {resp.status}")
                        number = (await resp.json())["number"]
                    tstate[finding_key(target, f)] = number
                    self._save(state)
                    report["created"].append(number)
                except Exception as exc:
                    report["errors"].append(f"create {f.get('title')!r}: {type(exc).__name__} {exc}")

            for key, number in plan["close"]:
                try:
                    async with session.post(f"{base}/{number}/comments",
                                            json={"body": f"No longer detected as of scan `{scan_id}`. Closing."}) as resp:
                        if resp.status != 201:
                            raise TicketingError(f"comment HTTP {resp.status}")
                    async with session.patch(f"{base}/{number}", json={"state": "closed", "state_reason": "completed"}) as resp:
                        if resp.status != 200:
                            raise TicketingError(f"close HTTP {resp.status}")
                    tstate.pop(key, None)
                    self._save(state)
                    report["closed"].append(number)
                except Exception as exc:
                    report["errors"].append(f"close #{number}: {type(exc).__name__} {exc}")
        return report
