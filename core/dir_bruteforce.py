"""
VulnForge Directory/File Brute-Force
Probes a wordlist of common paths against the target, bounded by a
concurrency cap and a hard request ceiling, and reuses the same
soft-404/catch-all baseline logic as the sensitive-path check
(web_validators.is_catch_all) so SPA/catch-all routers that answer 200 for
everything don't flood the report with false positives.

Off by default — unlike the fixed sensitive-path list (which only probes a
few dozen known-sensitive files), a brute-force run can mean thousands of
requests against a target, which is noisier and more likely to trip rate
limiting/WAFs. Enable explicitly:

  "web": {"dir_bruteforce": {"enabled": true, "wordlist_path": null}}

wordlist_path accepts any external wordlist (e.g. SecLists); null falls
back to the small built-in list at data/wordlists/common.txt.
"""
import asyncio
import logging
import uuid
from pathlib import Path
from urllib.parse import urljoin

import aiohttp

from .web_validators import fingerprint, is_catch_all, is_directory_listing

logger = logging.getLogger("vulnforge.dir_bruteforce")

BUILTIN_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "wordlists" / "common.txt"

FALLBACK_WORDS = [
    "admin", "backup", "api", "test", "login", "uploads", "config", "old",
    "dev", "staging", ".git", "wp-admin", ".well-known", "images", "static",
]

INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403}


class DirBruteforce:
    def __init__(self, config: dict):
        cfg = (config.get("web", {}) or {}).get("dir_bruteforce", {}) or {}
        self.enabled = cfg.get("enabled", False)
        self.wordlist_path = cfg.get("wordlist_path")
        self.extensions = cfg.get("extensions", [""]) or [""]
        self.max_concurrency = max(1, int(cfg.get("max_concurrency", 10)))
        self.max_requests = int(cfg.get("max_requests", 2000))

    def _load_words(self) -> list[str]:
        path = Path(self.wordlist_path) if self.wordlist_path else BUILTIN_WORDLIST
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            words = [w.strip() for w in lines if w.strip() and not w.startswith("#")]
            if words:
                return words
        except OSError:
            pass
        logger.warning(f"Wordlist unavailable at {path}; using tiny built-in fallback list")
        return list(FALLBACK_WORDS)

    def _build_paths(self) -> list[str]:
        words = self._load_words()
        paths: list[str] = []
        for w in words:
            w = w.lstrip("/")
            for ext in self.extensions:
                paths.append(f"/{w}{ext}")
        # Dedupe while preserving order, then cap.
        seen: set[str] = set()
        deduped = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        return deduped[: self.max_requests]

    async def run(self, session: aiohttp.ClientSession, base_url: str, findings: list):
        if not self.enabled:
            return

        paths = self._build_paths()
        if not paths:
            return

        baseline = None
        try:
            probe_path = "/vf-brute-" + uuid.uuid4().hex[:12]
            async with session.get(urljoin(base_url, probe_path), allow_redirects=False) as resp:
                body = await resp.content.read(65536)
                baseline = (resp.status, *fingerprint(body))
        except Exception:
            pass

        sem = asyncio.Semaphore(self.max_concurrency)
        hits = 0

        async def probe(path: str):
            nonlocal hits
            async with sem:
                url = urljoin(base_url, path)
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        if resp.status not in INTERESTING_STATUS:
                            return
                        body = await resp.content.read(65536)
                        if is_catch_all(baseline, resp.status, body):
                            return
                        hits += 1
                        self._record(path, url, resp.status, body, findings)
                except Exception:
                    pass

        await asyncio.gather(*[probe(p) for p in paths])
        logger.info(f"dir_bruteforce: {len(paths)} paths tried, {hits} finding(s) on {base_url}")

    @staticmethod
    def _record(path: str, url: str, status: int, body: bytes, findings: list):
        if status in (200, 201, 204):
            listing = is_directory_listing(body[:65536].decode("utf-8", "replace"))
            findings.append({
                "title": f"Brute-Forced Path Reachable: {path}",
                "severity": "medium" if listing else "low",
                "description": f"{url} returned HTTP {status}" + (" with directory listing enabled" if listing else "") + ".",
                "remediation": f"Remove or restrict access to {path} if it isn't meant to be public; "
                               f"disable directory listing if enabled.",
                "category": "dir_bruteforce",
                "confidence": "medium",
                "evidence": f"GET {url} -> HTTP {status}, {len(body)} bytes",
            })
        else:
            findings.append({
                "title": f"Brute-Forced Path Restricted: {path}",
                "severity": "info",
                "description": f"{url} returned HTTP {status} — the path exists but access is "
                                f"restricted (redirect/auth-required/forbidden).",
                "remediation": "No action required if restriction is intentional; confirm the "
                               "path isn't an unintentionally exposed admin/legacy endpoint.",
                "category": "dir_bruteforce",
                "confidence": "low",
                "evidence": f"GET {url} -> HTTP {status}",
            })
