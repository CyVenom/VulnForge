"""
VulnForge Plugin — HTTP Methods Checker
Tests for dangerous HTTP methods: TRACE, PUT, DELETE, CONNECT, OPTIONS.
"""
import asyncio
import logging
from typing import TYPE_CHECKING

import aiohttp

from core.plugin_manager import VulnForgePlugin

if TYPE_CHECKING:
    from core.scanner import ScanResult

logger = logging.getLogger("vulnforge.plugins.http_methods")

DANGEROUS_METHODS = {
    "TRACE": ("medium", "TRACE reflects request back — XST (cross-site tracing) risk."),
    "PUT": ("high", "HTTP PUT allows arbitrary file uploads."),
    "DELETE": ("high", "HTTP DELETE allows file deletion."),
    "CONNECT": ("medium", "HTTP CONNECT may allow proxy tunnelling."),
}


class HTTPMethodsPlugin(VulnForgePlugin):
    name = "http_methods"
    description = "Detects dangerous HTTP methods enabled on the server"
    version = "1.0.0"
    author = "VulnForge"

    async def run(self, target: str, scan_result: "ScanResult") -> dict:
        if not target.startswith(("http://", "https://")):
            url = f"https://{target}"
        else:
            url = target

        findings: list[dict] = []
        allowed_methods: list[str] = []
        data: dict = {}

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # First check OPTIONS
            try:
                async with session.options(url) as resp:
                    allow_header = resp.headers.get("Allow", "")
                    data["options_allow_header"] = allow_header
                    allowed_methods = [m.strip() for m in allow_header.split(",") if m.strip()]
            except Exception as exc:
                logger.debug(f"OPTIONS request failed: {exc}")

            # Test dangerous methods directly
            tasks = [
                self._test_method(session, url, method, findings)
                for method in DANGEROUS_METHODS
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        data["allowed_methods"] = allowed_methods
        data["tested_methods"] = list(DANGEROUS_METHODS.keys())

        return {"findings": findings, "data": data}

    async def _test_method(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        findings: list,
    ):
        severity, description = DANGEROUS_METHODS[method]
        try:
            async with session.request(method, url, allow_redirects=False) as resp:
                # 405 = Method Not Allowed (good), 501 = Not Implemented (good)
                if resp.status not in (405, 501, 400):
                    findings.append({
                        "title": f"Dangerous HTTP Method Enabled: {method}",
                        "severity": severity,
                        "description": description,
                        "remediation": f"Disable HTTP {method} in web server configuration.",
                        "category": "http_methods",
                        "evidence": f"{method} {url} → HTTP {resp.status}",
                    })
        except aiohttp.ClientConnectorError:
            pass
        except Exception as exc:
            logger.debug(f"{method} test error: {exc}")
