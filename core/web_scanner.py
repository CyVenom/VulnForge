"""
VulnForge Web Scanner Module
Detects common web vulnerabilities: missing security headers, cookie flags,
open redirects, directory listing, server info disclosure, JWT weaknesses,
CSP effectiveness, and more.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re
import uuid
from urllib.parse import urlparse, urljoin

import aiohttp

from .active_probes import ActiveProbes
from .dir_bruteforce import DirBruteforce
from .web_fingerprint import check_cms, check_graphql
from .web_validators import (
    SENSITIVE_CHECKS, check_sensitive, find_stack_trace, fingerprint,
    is_catch_all, is_directory_listing,
)

logger = logging.getLogger("vulnforge.web_scanner")

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# A small list of commonly-used/leaked JWT HMAC secrets — authorized testing
# only. This checks whether a token's signature validates against any of
# these, i.e. a trivially guessable signing secret.
COMMON_JWT_SECRETS = [
    "secret", "secret123", "password", "123456", "changeme", "jwt_secret",
    "your-256-bit-secret", "supersecret", "mysecret", "test", "dev",
]

# Security headers that should be present
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS not set — site vulnerable to protocol downgrade attacks.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP missing — increased XSS risk.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options missing — clickjacking risk.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options missing — MIME sniffing risk.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy not set — may leak sensitive URLs.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy not set — browser features uncontrolled.",
    },
}

# Headers that should NOT be present (info disclosure)
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

# Paths probed for exposure. Each has a content validator in web_validators.py;
# a bare HTTP 200 is never enough on its own.
SENSITIVE_PATHS = list(SENSITIVE_CHECKS)


class WebScanner:
    """Async web vulnerability scanner."""

    def __init__(self, config: dict):
        self.config = config
        self.web_cfg = config.get("web", {})
        self.timeout = aiohttp.ClientTimeout(total=self.web_cfg.get("timeout", 15))
        self.user_agent = self.web_cfg.get("user_agent", "VulnForge/1.0.0")
        self.active_probes = ActiveProbes(config)
        self.dir_bruteforce = DirBruteforce(config)

    async def scan(self, target: str) -> dict:
        """Run all web checks against target."""
        # Normalise target to URL
        if not target.startswith(("http://", "https://")):
            urls = [f"https://{target}", f"http://{target}"]
        else:
            urls = [target]

        base_url = None
        response_data = None

        connector = aiohttp.TCPConnector(ssl=False, limit=20)
        headers = {"User-Agent": self.user_agent}

        async with aiohttp.ClientSession(
            connector=connector,
            headers=headers,
            timeout=self.timeout,
        ) as session:
            for url in urls:
                try:
                    async with session.get(url, allow_redirects=True, max_redirects=5) as resp:
                        base_url = str(resp.url)
                        response_data = {
                            "status": resp.status,
                            "headers": dict(resp.headers),
                            "url": base_url,
                            "body_snippet": (await resp.text(errors="replace"))[:2000],
                        }
                    break
                except Exception as exc:
                    logger.debug(f"Could not reach {url}: {exc}")

            if not response_data:
                return {
                    "error": f"Could not connect to {target}",
                    "findings": [],
                    "checks_performed": 0,
                }

            findings: list[dict] = []
            tasks = [
                self._check_security_headers(response_data, findings),
                self._check_info_disclosure(response_data, findings),
                self._check_cookie_flags(session, base_url, findings),
                self._check_cors(session, base_url, findings),
                self._check_open_redirect(session, base_url, findings),
                self._check_directory_listing(session, base_url, findings),
                self._check_jwt(response_data, findings),
                self._check_csp_quality(response_data, findings),
                check_graphql(session, base_url, findings),
                check_cms(session, base_url, response_data, findings),
                self.active_probes.run(session, base_url, findings),
            ]
            if self.web_cfg.get("check_sensitive_paths", True):
                tasks.append(self._check_sensitive_paths(session, base_url, findings))
            if self.dir_bruteforce.enabled:
                tasks.append(self.dir_bruteforce.run(session, base_url, findings))

            await asyncio.gather(*tasks, return_exceptions=True)

        return {
            "target": target,
            "base_url": base_url,
            "http_status": response_data.get("status"),
            "findings": findings,
            "checks_performed": len(tasks),
        }

    async def _check_security_headers(self, response_data: dict, findings: list):
        headers = {k.lower(): v for k, v in response_data.get("headers", {}).items()}
        is_https = str(response_data.get("url", "")).lower().startswith("https://")
        csp = headers.get("content-security-policy", "").lower()

        if not is_https:
            findings.append({
                "title": "HTTPS Not Available (Plain HTTP Only)",
                "severity": "medium",
                "description": "The site could only be reached over plain HTTP, so traffic is unencrypted and "
                               "browsers ignore HSTS on HTTP responses.",
                "remediation": "Serve the site over HTTPS with a valid certificate and redirect HTTP to it.",
                "category": "transport",
                "evidence": f"Final URL after redirects: {response_data.get('url')}",
            })

        for header, meta in REQUIRED_SECURITY_HEADERS.items():
            if header.lower() in headers:
                continue
            if header == "Strict-Transport-Security" and not is_https:
                continue  # meaningless over HTTP; covered by the finding above
            if header == "X-Frame-Options" and "frame-ancestors" in csp:
                continue  # CSP frame-ancestors supersedes it
            findings.append({
                "title": f"Missing Security Header: {header}",
                "severity": meta["severity"],
                "description": meta["description"],
                "remediation": f"Add '{header}' response header with appropriate value.",
                "category": "security_headers",
            })

    async def _check_info_disclosure(self, response_data: dict, findings: list):
        headers = response_data.get("headers", {})
        for header in DISCLOSURE_HEADERS:
            val = headers.get(header) or headers.get(header.lower())
            if val:
                findings.append({
                    "title": f"Server Information Disclosure: {header}",
                    "severity": "low",
                    "description": f"Header '{header}: {val}' reveals server technology.",
                    "remediation": f"Remove or obfuscate the '{header}' response header.",
                    "category": "info_disclosure",
                    "evidence": f"{header}: {val}",
                })

        body = response_data.get("body_snippet", "")
        trace = find_stack_trace(body)
        if trace:
            findings.append({
                "title": "Stack Trace / Debug Error Exposure",
                "severity": "medium",
                "description": "The response body contains what looks like a server-side stack trace or debug error.",
                "remediation": "Configure production error handling to suppress detailed errors.",
                "category": "info_disclosure",
                "evidence": trace,
            })

    async def _check_cookie_flags(self, session: aiohttp.ClientSession, url: str, findings: list):
        try:
            async with session.get(url) as resp:
                for cookie in resp.cookies.values():
                    name = cookie.key
                    if not cookie.get("secure"):
                        findings.append({
                            "title": f"Cookie Missing Secure Flag: {name}",
                            "severity": "medium",
                            "description": f"Cookie '{name}' transmitted over plain HTTP.",
                            "remediation": "Set Secure flag on all cookies.",
                            "category": "cookies",
                        })
                    if not cookie.get("httponly"):
                        findings.append({
                            "title": f"Cookie Missing HttpOnly Flag: {name}",
                            "severity": "medium",
                            "description": f"Cookie '{name}' accessible via JavaScript (XSS risk).",
                            "remediation": "Set HttpOnly flag on session cookies.",
                            "category": "cookies",
                        })
                    samesite = cookie.get("samesite", "").lower()
                    if samesite not in ("strict", "lax"):
                        findings.append({
                            "title": f"Cookie SameSite Not Strict/Lax: {name}",
                            "severity": "low",
                            "description": f"Cookie '{name}' SameSite={samesite or 'None'} — CSRF risk.",
                            "remediation": "Set SameSite=Strict or SameSite=Lax on cookies.",
                            "category": "cookies",
                        })
        except Exception as exc:
            logger.debug(f"Cookie check failed: {exc}")

    async def _check_sensitive_paths(self, session: aiohttp.ClientSession, base_url: str, findings: list):
        # Baseline: ask for a path that cannot exist. If the site answers 200
        # for it too, it is a catch-all router and a 200 proves nothing.
        baseline = None
        try:
            async with session.get(urljoin(base_url, "/vf-" + uuid.uuid4().hex[:12]), allow_redirects=False) as resp:
                body = await resp.content.read(65536)
                baseline = (resp.status, *fingerprint(body))
        except Exception:
            pass

        async def probe(path: str):
            url = urljoin(base_url, path)
            try:
                async with session.get(url, allow_redirects=False) as resp:
                    body = await resp.content.read(65536)
                    if is_catch_all(baseline, resp.status, body):
                        return
                    verdict = check_sensitive(path, resp.status, body)
                    if verdict:
                        severity, reason = verdict
                        findings.append({
                            "title": f"Sensitive Path Exposed: {path}",
                            "severity": severity,
                            "description": f"{reason} at {url}.",
                            "remediation": f"Remove or restrict access to {path}",
                            "category": "sensitive_files",
                            "evidence": f"HTTP 200 at {url}; content check passed ({reason})",
                        })
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in SENSITIVE_PATHS])

    async def _check_cors(self, session: aiohttp.ClientSession, url: str, findings: list):
        try:
            async with session.get(
                url,
                headers={"Origin": "https://evil.example.com"},
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*":
                    findings.append({
                        "title": "CORS Wildcard Origin Allowed",
                        "severity": "medium",
                        "description": "Access-Control-Allow-Origin: * allows any origin.",
                        "remediation": "Restrict CORS to known origins.",
                        "category": "cors",
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                    })
                if "evil.example.com" in acao and "true" in acac.lower():
                    findings.append({
                        "title": "CORS Misconfiguration — Arbitrary Origin with Credentials",
                        "severity": "high",
                        "description": "Server reflects arbitrary Origin and allows credentials.",
                        "remediation": "Validate Origin header against a whitelist.",
                        "category": "cors",
                        "evidence": f"ACAO: {acao}, ACAC: {acac}",
                    })
        except Exception as exc:
            logger.debug(f"CORS check failed: {exc}")

    async def _check_open_redirect(self, session: aiohttp.ClientSession, url: str, findings: list):
        test_params = [
            "?redirect=https://evil.example.com",
            "?url=https://evil.example.com",
            "?next=https://evil.example.com",
            "?return=https://evil.example.com",
        ]
        for param in test_params:
            try:
                async with session.get(
                    url + param,
                    allow_redirects=False,
                ) as resp:
                    location = resp.headers.get("Location", "")
                    if resp.status in (301, 302, 303, 307, 308) and "evil.example.com" in location:
                        findings.append({
                            "title": "Open Redirect Detected",
                            "severity": "medium",
                            "description": f"Parameter in {param} caused redirect to {location}.",
                            "remediation": "Validate redirect destinations against a whitelist.",
                            "category": "open_redirect",
                            "evidence": f"GET {url + param} → {resp.status} {location}",
                        })
                        break
            except Exception:
                pass

    async def _check_directory_listing(self, session: aiohttp.ClientSession, url: str, findings: list):
        test_paths = ["/images/", "/uploads/", "/files/", "/static/", "/assets/"]
        for path in test_paths:
            try:
                async with session.get(urljoin(url, path)) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        if is_directory_listing(body):
                            findings.append({
                                "title": f"Directory Listing Enabled: {path}",
                                "severity": "medium",
                                "description": f"Directory listing is enabled at {path}.",
                                "remediation": "Disable directory listing in web server config.",
                                "category": "directory_listing",
                                "evidence": f"HTTP 200 with directory listing at {urljoin(url, path)}",
                            })
            except Exception:
                pass

    async def _check_jwt(self, response_data: dict, findings: list):
        """
        Scan the response body/headers for JWTs and flag common weaknesses:
        alg=none, missing expiry, and signatures that validate against a
        short list of commonly-leaked HMAC secrets.
        """
        haystacks = [response_data.get("body_snippet", "")]
        headers = response_data.get("headers", {})
        for key, val in headers.items():
            if key.lower() in ("set-cookie", "authorization"):
                haystacks.append(str(val))

        tokens = set()
        for text in haystacks:
            tokens.update(JWT_PATTERN.findall(text or ""))

        for token in tokens:
            try:
                parts = token.split(".")
                if len(parts) != 3 or not parts[1]:
                    continue
                header = self._decode_jwt_segment(parts[0])
                payload = self._decode_jwt_segment(parts[1])
                if header is None or payload is None:
                    continue

                alg = str(header.get("alg", "")).lower()
                evidence = f"JWT (truncated): {token[:40]}..."

                if alg == "none":
                    findings.append({
                        "title": "JWT Uses 'alg: none'",
                        "severity": "critical",
                        "description": "Token header specifies alg=none — signature verification "
                                        "can be bypassed entirely by crafting an unsigned token.",
                        "remediation": "Reject tokens with alg=none server-side; enforce an explicit allow-list of algorithms.",
                        "category": "jwt",
                        "evidence": evidence,
                    })

                if "exp" not in payload:
                    findings.append({
                        "title": "JWT Missing Expiry Claim",
                        "severity": "medium",
                        "description": "Token has no 'exp' claim — it never expires once issued.",
                        "remediation": "Always set a short-lived 'exp' claim on issued tokens.",
                        "category": "jwt",
                        "evidence": evidence,
                    })

                if alg.startswith("hs") and len(parts[2]) > 0:
                    weak_secret = self._find_weak_jwt_secret(parts[0], parts[1], parts[2], alg)
                    if weak_secret:
                        findings.append({
                            "title": "JWT Signed With Weak/Guessable Secret",
                            "severity": "critical",
                            "description": f"Token signature validates against a common/weak secret ({weak_secret!r}).",
                            "remediation": "Rotate the signing secret to a long, random value (32+ bytes) and keep it out of source control.",
                            "category": "jwt",
                            "evidence": evidence,
                        })
            except Exception as exc:
                logger.debug(f"JWT check error: {exc}")

    @staticmethod
    def _decode_jwt_segment(segment: str) -> dict | None:
        try:
            padded = segment + "=" * (-len(segment) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    @staticmethod
    def _find_weak_jwt_secret(header_b64: str, payload_b64: str, sig_b64: str, alg: str) -> str | None:
        """Try HS256/HS384/HS512 against a short list of common secrets."""
        hash_fn = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}.get(alg)
        if not hash_fn:
            return None

        signing_input = f"{header_b64}.{payload_b64}".encode()
        try:
            padded = sig_b64 + "=" * (-len(sig_b64) % 4)
            expected_sig = base64.urlsafe_b64decode(padded)
        except Exception:
            return None

        for secret in COMMON_JWT_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, expected_sig):
                return secret
        return None

    async def _check_csp_quality(self, response_data: dict, findings: list):
        """
        Go beyond presence-only CSP checking: parse directives and flag
        patterns that significantly weaken the policy's protection.
        """
        headers = {k.lower(): v for k, v in response_data.get("headers", {}).items()}
        csp = headers.get("content-security-policy")
        if not csp:
            return  # absence is already flagged by _check_security_headers

        directives: dict[str, list[str]] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            directives[tokens[0].lower()] = tokens[1:]

        issues = []

        for directive in ("script-src", "default-src"):
            values = directives.get(directive)
            if values is None:
                continue
            if "'unsafe-inline'" in values:
                issues.append(f"{directive} allows 'unsafe-inline' (inline script XSS protection bypassed)")
            if "'unsafe-eval'" in values:
                issues.append(f"{directive} allows 'unsafe-eval' (eval()-based XSS protection bypassed)")
            if "*" in values:
                issues.append(f"{directive} allows wildcard '*' source")

        if "object-src" not in directives and "default-src" not in directives:
            issues.append("no object-src or default-src restriction (Flash/plugin injection risk)")

        if "base-uri" not in directives:
            issues.append("no base-uri directive (base tag injection can redirect relative URLs)")

        if issues:
            findings.append({
                "title": "Weak Content-Security-Policy Configuration",
                "severity": "medium",
                "description": "CSP header is present but weakened by: " + "; ".join(issues) + ".",
                "remediation": "Tighten CSP: avoid 'unsafe-inline'/'unsafe-eval', avoid wildcard sources, "
                               "and set explicit object-src/base-uri directives.",
                "category": "csp",
                "evidence": csp[:300],
            })
