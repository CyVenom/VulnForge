"""
VulnForge Ticketing (Jira)
Jira counterpart to core/ticketing.py's GitHub Issues sync — same dry-run-
by-default, dedup-by-stable-key, evidence-excluded-unless-opted-in design,
targeting the Jira Cloud REST API (v2) instead of GitHub Issues.

Safety: identical contract to GitHubTicketing — dry run unless apply=True,
token/API key only from an environment variable, evidence excluded from
issue bodies unless ticketing.include_evidence is true.

config.json:
  "ticketing": {
    "enabled": true, "provider": "jira", "min_severity": "high",
    "labels": ["vulnforge"], "include_evidence": false,
    "jira": {
      "base_url": "https://yourteam.atlassian.net",
      "project_key": "SEC",
      "issue_type": "Bug",
      "email_env": "JIRA_EMAIL",
      "token_env": "JIRA_API_TOKEN",
      "done_transition_names": ["Done", "Closed", "Resolve"]
    }
  }
"""
import json
import logging
import os
from pathlib import Path

import aiohttp

from .notifier import _rank
from .ticketing import finding_key

logger = logging.getLogger("vulnforge.ticketing_jira")


class TicketingError(Exception):
    pass


class JiraTicketing:
    def __init__(self, config: dict, state_path: str | None = None):
        cfg = config.get("ticketing", {})
        jcfg = cfg.get("jira", {}) or {}
        self.enabled = cfg.get("enabled", False)
        self.min_severity = cfg.get("min_severity", "high")
        self.labels = list(cfg.get("labels", ["vulnforge"]))
        self.include_evidence = cfg.get("include_evidence", False)

        self.base_url = (jcfg.get("base_url") or "").rstrip("/")
        self.project_key = jcfg.get("project_key", "")
        self.issue_type = jcfg.get("issue_type", "Bug")
        self.email = os.environ.get(jcfg.get("email_env", "JIRA_EMAIL"), "")
        self.token = os.environ.get(jcfg.get("token_env", "JIRA_API_TOKEN"), "")
        self.done_transition_names = [n.lower() for n in jcfg.get("done_transition_names", ["done", "closed", "resolve"])]

        reports = config.get("reporting", {}).get("output_dir", "reports")
        self.state_path = Path(state_path or Path(reports) / "ticket_state_jira.json")

    def _load(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def plan(self, target: str, findings: list[dict]) -> dict:
        threshold = _rank(self.min_severity)
        state = self._load().get(target, {})
        current = {finding_key(target, f): f for f in findings if _rank(f.get("severity")) >= threshold}
        create = [f for k, f in current.items() if k not in state]
        close = [(k, key) for k, key in state.items() if k not in current]
        return {"create": create, "close": close, "existing": len(set(current) & set(state))}

    def render(self, scan_id: str, target: str, f: dict) -> dict:
        sev = f.get("severity", "info")
        lines = [
            f"vulnforge-key:{finding_key(target, f)}",
            f"Severity: {sev.upper()}",
            f"Target: {target}",
            f"First seen in scan: {scan_id}",
            "",
            f.get("description", ""),
            "",
            "Remediation:",
            f.get("remediation", "See scan report."),
        ]
        if self.include_evidence and f.get("evidence"):
            lines += ["", "Evidence:", str(f["evidence"])]
        lines += ["", "Opened automatically by VulnForge. Verify manually before acting; automated findings can be false positives."]
        return {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[VulnForge][{sev.upper()}] {f.get('title', 'Finding')} on {target}"[:250],
                "description": "\n".join(lines),
                "issuetype": {"name": self.issue_type},
                "labels": self.labels + [f"severity-{sev}"],
            }
        }

    def _auth(self) -> aiohttp.BasicAuth:
        return aiohttp.BasicAuth(self.email, self.token)

    async def sync(self, scan_id: str, target: str, findings: list[dict], apply: bool = False) -> dict:
        plan = self.plan(target, findings)
        report = {"applied": apply, "would_create": [f["title"] for f in plan["create"]],
                  "would_close": [key for _, key in plan["close"]], "existing": plan["existing"],
                  "created": [], "closed": [], "errors": []}
        if not apply:
            return report

        if not self.enabled or not self.base_url or not self.project_key:
            raise TicketingError("Jira ticketing is not enabled/configured (ticketing.enabled, ticketing.jira.base_url, ticketing.jira.project_key)")
        if not self.email or not self.token:
            raise TicketingError("no Jira email/API token found in the environment variables named by ticketing.jira.email_env/token_env")

        state = self._load()
        tstate = state.setdefault(target, {})

        async with aiohttp.ClientSession(auth=self._auth(), timeout=aiohttp.ClientTimeout(total=20)) as session:
            for f in plan["create"]:
                try:
                    async with session.post(f"{self.base_url}/rest/api/2/issue", json=self.render(scan_id, target, f)) as resp:
                        body = await resp.json()
                        if resp.status not in (200, 201):
                            raise TicketingError(f"HTTP {resp.status}: {body}")
                        issue_key = body["key"]
                    tstate[finding_key(target, f)] = issue_key
                    self._save(state)
                    report["created"].append(issue_key)
                except Exception as exc:
                    report["errors"].append(f"create {f.get('title')!r}: {type(exc).__name__} {exc}")

            for key, issue_key in plan["close"]:
                try:
                    await self._close_issue(session, issue_key, scan_id)
                    tstate.pop(key, None)
                    self._save(state)
                    report["closed"].append(issue_key)
                except Exception as exc:
                    report["errors"].append(f"close {issue_key}: {type(exc).__name__} {exc}")
        return report

    async def _close_issue(self, session: aiohttp.ClientSession, issue_key: str, scan_id: str):
        base = f"{self.base_url}/rest/api/2/issue/{issue_key}"
        async with session.post(f"{base}/comment", json={"body": f"No longer detected as of scan {scan_id}. Closing."}) as resp:
            if resp.status not in (200, 201):
                raise TicketingError(f"comment HTTP {resp.status}")

        async with session.get(f"{base}/transitions") as resp:
            if resp.status != 200:
                raise TicketingError(f"transitions HTTP {resp.status}")
            transitions = (await resp.json()).get("transitions", [])

        target_id = None
        for t in transitions:
            if t.get("name", "").lower() in self.done_transition_names:
                target_id = t["id"]
                break
        if target_id is None:
            logger.warning(f"No matching 'done' transition found for {issue_key}; left open with a closing comment only.")
            return

        async with session.post(f"{base}/transitions", json={"transition": {"id": target_id}}) as resp:
            if resp.status not in (200, 204):
                raise TicketingError(f"transition HTTP {resp.status}")
