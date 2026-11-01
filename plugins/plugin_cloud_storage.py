"""
VulnForge Plugin — Cloud Storage Misconfiguration
Derives candidate bucket/container names from the target's hostname and
checks S3, Google Cloud Storage, and Azure Blob for public read access.
This only ever issues GET requests to the cloud provider's own public
endpoints (never to the target itself) and never attempts to write or
delete anything — it answers "can anyone list/read this bucket", nothing more.

Opt out with "plugins": {"cloud_storage": {"enabled": false}} in config.json.
"""
import asyncio
import ipaddress
import logging
import re
from typing import TYPE_CHECKING

import aiohttp

from core.plugin_manager import VulnForgePlugin

if TYPE_CHECKING:
    from core.scanner import ScanResult

logger = logging.getLogger("vulnforge.plugins.cloud_storage")

SUFFIXES = ["", "-backup", "-backups", "-dev", "-prod", "-staging", "-assets",
            "-static", "-media", "-uploads", "-data", "-files", "-public", "-www"]

S3_LISTING = re.compile(r"<ListBucketResult", re.I)
S3_NO_SUCH_BUCKET = re.compile(r"<Code>NoSuchBucket</Code>", re.I)
S3_ACCESS_DENIED = re.compile(r"<Code>AccessDenied</Code>", re.I)

GCS_NOT_FOUND = re.compile(r"\"error\"\s*:\s*\{\s*\"code\"\s*:\s*404", re.S)
GCS_LISTING = re.compile(r'"kind"\s*:\s*"storage#objects"')

AZURE_LISTING = re.compile(r"<EnumerationResults", re.I)
AZURE_NOT_FOUND = re.compile(r"<Code>(ContainerNotFound|ResourceNotFound)</Code>", re.I)


class CloudStoragePlugin(VulnForgePlugin):
    name = "cloud_storage"
    description = "Public S3 / GCS / Azure Blob bucket misconfiguration discovery"
    version = "1.0.0"
    author = "VulnForge"

    def __init__(self, config: dict):
        super().__init__(config)
        self.cfg = config.get("plugins", {}).get("cloud_storage", {})

    def _enabled(self) -> bool:
        return self.cfg.get("enabled", True)

    async def run(self, target: str, scan_result: "ScanResult") -> dict:
        findings: list[dict] = []
        data: dict = {"checked": [], "public": []}

        if not self._enabled():
            return {"findings": findings, "data": data}

        hostname = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        if self._is_ip_or_local(hostname):
            return {"findings": findings, "data": data}

        base_name = hostname.split(".")[0] if "." in hostname else hostname
        base_name = re.sub(r"[^a-z0-9-]", "", base_name.lower())
        if not base_name:
            return {"findings": findings, "data": data}

        candidates = sorted({f"{base_name}{s}" for s in SUFFIXES})
        data["checked"] = candidates

        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = []
            for name in candidates:
                tasks.append(self._check_s3(session, name, findings, data))
                tasks.append(self._check_gcs(session, name, findings, data))
                tasks.append(self._check_azure(session, name, findings, data))
            await asyncio.gather(*tasks, return_exceptions=True)

        return {"findings": findings, "data": data}

    async def _get(self, session: aiohttp.ClientSession, url: str) -> tuple[int, str] | None:
        try:
            async with session.get(url, allow_redirects=False) as resp:
                body = await resp.text(errors="replace")
                return resp.status, body[:4096]
        except Exception:
            return None

    async def _check_s3(self, session, name, findings, data):
        result = await self._get(session, f"https://{name}.s3.amazonaws.com/")
        if result is None:
            return
        status, body = result
        if S3_NO_SUCH_BUCKET.search(body):
            return
        if status == 200 and S3_LISTING.search(body):
            data["public"].append(f"s3://{name}")
            findings.append(self._finding("Amazon S3", name, f"https://{name}.s3.amazonaws.com/", "listing"))
        elif S3_ACCESS_DENIED.search(body):
            findings.append(self._finding("Amazon S3", name, f"https://{name}.s3.amazonaws.com/", "exists", severity="info"))

    async def _check_gcs(self, session, name, findings, data):
        url = f"https://storage.googleapis.com/storage/v1/b/{name}/o"
        result = await self._get(session, url)
        if result is None:
            return
        status, body = result
        if GCS_NOT_FOUND.search(body):
            return
        if status == 200 and GCS_LISTING.search(body):
            data["public"].append(f"gcs://{name}")
            findings.append(self._finding("Google Cloud Storage", name, f"https://storage.googleapis.com/{name}/", "listing"))
        elif status == 403:
            findings.append(self._finding("Google Cloud Storage", name, f"https://storage.googleapis.com/{name}/", "exists", severity="info"))

    async def _check_azure(self, session, name, findings, data):
        azure_name = name.replace("-", "")
        if not azure_name:
            return
        url = f"https://{azure_name}.blob.core.windows.net/{name}?restype=container&comp=list"
        result = await self._get(session, url)
        if result is None:
            return
        status, body = result
        if AZURE_NOT_FOUND.search(body):
            return
        if status == 200 and AZURE_LISTING.search(body):
            data["public"].append(f"azure://{azure_name}/{name}")
            findings.append(self._finding("Azure Blob Storage", f"{azure_name}/{name}",
                                           f"https://{azure_name}.blob.core.windows.net/{name}", "listing"))

    @staticmethod
    def _finding(provider: str, name: str, url: str, kind: str, severity: str | None = None) -> dict:
        if kind == "listing":
            return {
                "title": f"Public {provider} Bucket With Listing Enabled: {name}",
                "severity": "high",
                "description": f"{provider} bucket/container {name!r} is readable by anyone and "
                                f"returns its full object listing, with no authentication.",
                "remediation": f"Restrict the bucket/container's access policy to authenticated "
                               f"principals only; disable public read/list access.",
                "category": "cloud_storage",
                "confidence": "confirmed",
                "evidence": f"GET {url} -> public object listing returned",
            }
        return {
            "title": f"{provider} Bucket Exists But Access Is Denied: {name}",
            "severity": severity or "low",
            "description": f"{provider} bucket/container {name!r} exists (derived from the target's "
                            f"name) but anonymous read access was refused. Confirms the name is in "
                            f"use; not itself a vulnerability.",
            "remediation": "No action required if access is intentionally restricted; "
                           "verify this isn't an unused bucket name someone else could claim.",
            "category": "cloud_storage",
            "confidence": "low",
            "evidence": f"GET {url} -> access denied (bucket exists)",
        }

    @staticmethod
    def _is_ip_or_local(hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return "." not in hostname or hostname.endswith((".local", ".localhost", ".internal"))
