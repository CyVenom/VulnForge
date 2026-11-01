"""
VulnForge Default Credential Checker
Tries a short, curated list of default/common credential pairs against
HTTP Basic Auth and FTP. This is active credential testing against a live
service — categorically more sensitive than everything else VulnForge does
by default — so it requires BOTH of:

  1. "credentials": {"enabled": true} in config.json, AND
  2. the --allow-credential-checks CLI flag on that specific run

Neither alone is enough; this is intentional friction so a successful login
is never a surprise. A successful login is reported at 'critical' severity
and nothing further is done with the session (no data is read/written).
"""
import asyncio
import ftplib
import logging

import aiohttp

logger = logging.getLogger("vulnforge.default_creds")

DEFAULT_HTTP_BASIC_PAIRS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", ""), ("root", "root"), ("test", "test"), ("user", "user"),
    ("guest", "guest"), ("admin", "changeme"),
]

DEFAULT_FTP_PAIRS = [
    ("anonymous", "anonymous"), ("anonymous", ""), ("ftp", "ftp"),
    ("admin", "admin"), ("admin", "password"),
]


class DefaultCredentialChecker:
    def __init__(self, config: dict):
        self.cfg = config.get("credentials", {}) or {}
        self.config_enabled = self.cfg.get("enabled", False)
        self.timeout = self.cfg.get("timeout", 8)
        self.http_pairs = [tuple(p) for p in self.cfg.get("http_basic_pairs", DEFAULT_HTTP_BASIC_PAIRS)]
        self.ftp_pairs = [tuple(p) for p in self.cfg.get("ftp_pairs", DEFAULT_FTP_PAIRS)]

    def enabled(self, cli_allowed: bool) -> bool:
        """Both the config flag and the explicit per-run CLI flag must agree."""
        return self.config_enabled and cli_allowed

    async def check(self, target: str, base_url: str | None, open_ports: set[int], cli_allowed: bool) -> list[dict]:
        if not self.enabled(cli_allowed):
            return []

        findings: list[dict] = []
        hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

        tasks = []
        if base_url:
            tasks.append(self._check_http_basic(base_url, findings))
        if not open_ports or 21 in open_ports:
            tasks.append(self._check_ftp(hostname, findings))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return findings

    async def _check_http_basic(self, base_url: str, findings: list):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(base_url, allow_redirects=False) as resp:
                    if resp.status != 401 or "basic" not in resp.headers.get("WWW-Authenticate", "").lower():
                        return  # not HTTP Basic Auth-protected; nothing to try

                for user, pwd in self.http_pairs:
                    try:
                        async with session.get(base_url, auth=aiohttp.BasicAuth(user, pwd), allow_redirects=False) as resp:
                            if resp.status != 401:
                                findings.append({
                                    "title": "Default/Weak Credentials Accepted (HTTP Basic Auth)",
                                    "severity": "critical",
                                    "description": f"HTTP Basic Auth at {base_url} accepted the "
                                                    f"credential pair {user!r}/{'*' * len(pwd) if pwd else '(empty)'}.",
                                    "remediation": "Change this account's password immediately and "
                                                   "audit for unauthorized access; enforce a strong "
                                                   "password policy and consider disabling Basic Auth "
                                                   "in favor of a proper auth scheme.",
                                    "category": "default_credentials",
                                    "confidence": "confirmed",
                                    "evidence": f"GET {base_url} with Basic {user}:{'*' * len(pwd) if pwd else ''} -> HTTP {resp.status}",
                                })
                                return
                    except Exception as exc:
                        logger.debug(f"HTTP basic auth probe error: {exc}")
        except Exception as exc:
            logger.debug(f"HTTP basic auth check failed: {exc}")

    async def _check_ftp(self, hostname: str, findings: list):
        loop = asyncio.get_event_loop()
        for user, pwd in self.ftp_pairs:
            try:
                ok = await loop.run_in_executor(None, self._try_ftp_login, hostname, user, pwd)
            except Exception as exc:
                logger.debug(f"FTP probe error: {exc}")
                continue
            if ok:
                findings.append({
                    "title": "Default/Weak Credentials Accepted (FTP)",
                    "severity": "critical",
                    "description": f"FTP service on {hostname} accepted the credential pair "
                                    f"{user!r}/{'*' * len(pwd) if pwd else '(empty)'}.",
                    "remediation": "Disable this account or change its password immediately; "
                                   "disable anonymous FTP if not explicitly required.",
                    "category": "default_credentials",
                    "confidence": "confirmed",
                    "evidence": f"FTP login {user}:{'*' * len(pwd) if pwd else ''}@{hostname}:21 -> accepted",
                })
                return  # one confirmed hit is enough

    def _try_ftp_login(self, hostname: str, user: str, pwd: str) -> bool:
        try:
            ftp = ftplib.FTP(timeout=self.timeout)
            ftp.connect(hostname, 21)
            ftp.login(user, pwd)
            ftp.quit()
            return True
        except Exception:
            return False
