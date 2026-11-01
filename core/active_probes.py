"""
VulnForge Active Probes
Safe, non-destructive canary checks for reflected XSS, SQL injection, SSRF,
and OS command injection. Every payload is inert: XSS uses a random marker
with no executable script, SQLi only sends single characters/boolean
operators and looks for a signature error or a length delta, SSRF only
targets well-known metadata/loopback endpoints and looks for their own
response signatures being reflected back, and command injection uses a
harmless `echo <random-token>` so a false positive never does more than
print a string. Nothing here writes, deletes, or executes a real payload
against the target's own logic — these are canaries, not exploits.

Opt out with "web": {"active_probes": {"enabled": false}} in config.json.
"""
import asyncio
import logging
import re
import uuid
from urllib.parse import urljoin

import aiohttp

logger = logging.getLogger("vulnforge.active_probes")

# A conservative set of commonly-vulnerable parameter names. Capped by
# max_params so a single scan never fires an unbounded number of requests.
DEFAULT_PARAM_NAMES = [
    "id", "q", "search", "query", "name", "category", "file", "path",
    "page", "lang", "cmd", "url", "callback", "webhook", "host", "ip",
    "target", "redirect", "next", "data", "input",
]

# SQL error signatures beyond the generic stack-trace patterns in
# web_validators — these are specific enough to not be "just the word error".
SQLI_ERROR_PATTERNS = [
    re.compile(r"You have an error in your SQL syntax", re.I),
    re.compile(r"\bORA-\d{5}:"),
    re.compile(r"unterminated quoted string at or near", re.I),
    re.compile(r"unrecognized token:", re.I),
    re.compile(r"SQLite3::query\(\)|SQLSTATE\[", re.I),
    re.compile(r"Microsoft OLE DB Provider for (ODBC Drivers|SQL Server)", re.I),
    re.compile(r"PostgreSQL.*?ERROR", re.I | re.S),
    re.compile(r"Warning.*?\Wmysqli?_", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"pg_query\(\)|pg_exec\(\)", re.I),
]

# SSRF: well-known internal/metadata endpoints and a signature that only
# appears if the server actually fetched them and leaked the response back.
SSRF_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/", re.compile(r"ami-id|instance-id|iam/security-credentials", re.I)),
    ("http://metadata.google.internal/computeMetadata/v1/", re.compile(r"computeMetadata|project-id", re.I)),
    ("file:///etc/passwd", re.compile(r"root:.*:0:0:")),
]


def _find_sqli_signature(body: str) -> str | None:
    for pattern in SQLI_ERROR_PATTERNS:
        m = pattern.search(body)
        if m:
            return m.group(0)[:120]
    return None


class ActiveProbes:
    def __init__(self, config: dict):
        cfg = (config.get("web", {}) or {}).get("active_probes", {}) or {}
        self.enabled = cfg.get("enabled", True)
        self.param_names = list(cfg.get("params", DEFAULT_PARAM_NAMES))
        self.max_params = cfg.get("max_params", 8)

    async def run(self, session: aiohttp.ClientSession, base_url: str, findings: list):
        if not self.enabled:
            return
        params = self.param_names[: self.max_params]
        await asyncio.gather(
            *[self._probe_param(session, base_url, p, findings) for p in params],
            return_exceptions=True,
        )

    async def _get(self, session: aiohttp.ClientSession, url: str) -> tuple[int, str] | None:
        try:
            async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                body = await resp.text(errors="replace")
                return resp.status, body[:65536]
        except Exception:
            return None

    async def _probe_param(self, session: aiohttp.ClientSession, base_url: str, param: str, findings: list):
        baseline = await self._get(session, f"{base_url}?{param}=vfbaseline")
        if baseline is None:
            return
        base_status, base_body = baseline

        await asyncio.gather(
            self._probe_xss(session, base_url, param, base_body, findings),
            self._probe_sqli(session, base_url, param, base_status, base_body, findings),
            self._probe_ssrf(session, base_url, param, base_body, findings),
            self._probe_cmdi(session, base_url, param, base_body, findings),
            return_exceptions=True,
        )

    async def _probe_xss(self, session, base_url, param, base_body, findings):
        token = uuid.uuid4().hex[:10]
        marker = f"<vfxss{token}>probe</vfxss{token}>"
        result = await self._get(session, f"{base_url}?{param}={marker}")
        if result is None:
            return
        _, body = result
        if marker in body and marker not in base_body:
            findings.append({
                "title": f"Reflected Input Without Encoding (Potential XSS): {param}",
                "severity": "medium",
                "description": f"A marker containing HTML-like syntax sent in the '{param}' parameter "
                                f"was reflected back in the response body without being HTML-encoded. "
                                f"This does not confirm script execution, but unescaped reflection is "
                                f"the precondition for reflected XSS.",
                "remediation": f"Context-aware output-encode the '{param}' parameter before rendering "
                               f"it in HTML (or use a templating engine that auto-escapes by default).",
                "category": "xss",
                "confidence": "medium",
                "evidence": f"GET {base_url}?{param}={marker[:40]}... -> marker found verbatim in body",
            })

    async def _probe_sqli(self, session, base_url, param, base_status, base_body, findings):
        # Error-based: a single quote should never appear in SQL unescaped.
        err_result = await self._get(session, f"{base_url}?{param}=vf'probe")
        if err_result is not None:
            _, err_body = err_result
            sig = _find_sqli_signature(err_body)
            if sig and not _find_sqli_signature(base_body):
                findings.append({
                    "title": f"SQL Error Triggered by Single-Quote Input: {param}",
                    "severity": "high",
                    "description": f"Sending a single quote in the '{param}' parameter produced a "
                                    f"database error in the response, indicating the input reaches a "
                                    f"SQL query without proper parameterization or escaping.",
                    "remediation": "Use parameterized queries / prepared statements for all "
                                   "database access; never build SQL via string concatenation.",
                    "category": "sqli",
                    "confidence": "high",
                    "evidence": f"GET {base_url}?{param}=vf'probe -> {sig!r} in response",
                })
                return  # error-based already confirms; skip the noisier boolean check

        # Boolean-based: compare an always-true vs always-false condition.
        true_result = await self._get(session, f"{base_url}?{param}=vf' OR '1'='1")
        false_result = await self._get(session, f"{base_url}?{param}=vf' AND '1'='2")
        if true_result is None or false_result is None:
            return
        t_status, t_body = true_result
        f_status, f_body = false_result
        if t_status != f_status or (
            t_body != f_body and abs(len(t_body) - len(f_body)) > max(32, int(len(base_body) * 0.05))
        ):
            findings.append({
                "title": f"Possible Boolean-Based SQL Injection: {param}",
                "severity": "medium",
                "description": f"The '{param}' parameter produced a different response for an "
                                f"always-true vs. always-false SQL condition (status {t_status} vs "
                                f"{f_status}, body length {len(t_body)} vs {len(f_body)}). This is a "
                                f"heuristic signal, not a confirmed injection.",
                "remediation": "Use parameterized queries / prepared statements; verify manually "
                               "with sqlmap or a time-based payload under authorization.",
                "category": "sqli",
                "confidence": "low",
                "evidence": f"GET {base_url}?{param}=vf' OR '1'='1 ({t_status}, {len(t_body)}b) vs "
                            f"vf' AND '1'='2 ({f_status}, {len(f_body)}b)",
            })

    async def _probe_ssrf(self, session, base_url, param, base_body, findings):
        for payload, signature in SSRF_TARGETS:
            result = await self._get(session, f"{base_url}?{param}={payload}")
            if result is None:
                continue
            _, body = result
            if signature.search(body) and not signature.search(base_body):
                findings.append({
                    "title": f"Server-Side Request Forgery (SSRF) Confirmed: {param}",
                    "severity": "critical",
                    "description": f"Setting the '{param}' parameter to {payload!r} caused the "
                                    f"server to fetch it and leak the response content back, "
                                    f"confirming the server will follow attacker-supplied URLs.",
                    "remediation": "Validate and allow-list destination hosts/schemes server-side "
                                   "before making any outbound request derived from user input; "
                                   "block link-local/metadata addresses explicitly.",
                    "category": "ssrf",
                    "confidence": "confirmed",
                    "evidence": f"GET {base_url}?{param}={payload} -> matched {signature.pattern!r} in response",
                })
                return  # one confirmed hit per param is enough

    async def _probe_cmdi(self, session, base_url, param, base_body, findings):
        token = f"VFCMD{uuid.uuid4().hex[:10]}"
        for payload in (f";echo {token}", f"|echo {token}", f"`echo {token}`", f"$(echo {token})"):
            result = await self._get(session, f"{base_url}?{param}={payload}")
            if result is None:
                continue
            _, body = result
            if token in body and token not in base_body:
                findings.append({
                    "title": f"OS Command Injection Confirmed: {param}",
                    "severity": "critical",
                    "description": f"A shell metacharacter payload in the '{param}' parameter caused "
                                    f"the server to execute 'echo {token}' and reflect its output, "
                                    f"confirming the input reaches a shell without sanitization.",
                    "remediation": "Never pass user input to a shell. Use language-level APIs "
                                   "(no shell=True / exec of a string) and strict input validation.",
                    "category": "command_injection",
                    "confidence": "confirmed",
                    "evidence": f"GET {base_url}?{param}={payload} -> {token!r} found in response",
                })
                return
