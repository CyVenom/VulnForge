"""
VulnForge CVE Sync
Builds data/cve_feed.json from two official sources:
  * NVD API 2.0 (NIST)   - CVE records with exact CPE version ranges
  * CISA KEV catalog     - CVEs known to be exploited in the wild

For each configured product it keeps CVEs scoring at or above min_cvss, plus
every KEV-listed CVE regardless of score, and stores the affected version
ranges so the matcher can compare a detected version precisely. Records that
cannot be evaluated (no version bounds, or only operating-system CPEs) are
skipped rather than guessed.

Products are "vendor:product" (precise CPE lookup) or a bare product name
(keyword lookup, filtered to exact CPE product matches).
"""
import asyncio
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

logger = logging.getLogger("vulnforge.cve_sync")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PAGE_SIZE = 2000
DELAY_NO_KEY = 6.5   # NVD allows 5 requests / 30 s without a key
DELAY_WITH_KEY = 0.7  # 50 requests / 30 s with one

DEFAULT_PRODUCTS = [
    "openbsd:openssh", "apache:http_server", "f5:nginx", "apache:tomcat", "isc:bind",
    "samba:samba", "exim:exim", "proftpd:proftpd", "vsftpd", "redis:redis", "php:php",
    "openssl:openssl", "oracle:mysql", "mariadb:mariadb", "postgresql:postgresql",
    "jenkins:jenkins", "haproxy:haproxy", "lighttpd:lighttpd", "dovecot:dovecot",
    "postfix:postfix", "mongodb:mongodb", "elastic:elasticsearch", "memcached:memcached",
    "squid-cache:squid", "microsoft:internet_information_services",
]


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def cvss_of(cve: dict) -> float:
    """Best available CVSS base score (v4 > v3.1 > v3.0 > v2), 0.0 if none."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            score = m.get("cvssData", {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return 0.0


def parse_cpe23(criteria: str) -> dict | None:
    """'cpe:2.3:a:vendor:product:version:update:...' -> parts (None if malformed)."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5]}


def extract_ranges(cve: dict, vendor: str | None, product: str) -> list[dict]:
    """
    Affected version ranges for one product, from vulnerable application CPE
    matches. Returns [{"si","se","ei","ee"}] (start/end, inclusive/exclusive),
    omitting unset bounds. Entries with no usable bound are dropped.
    """
    ranges: list[dict] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                cpe = parse_cpe23(m.get("criteria", ""))
                if not cpe or cpe["part"] != "a" or cpe["product"] != product:
                    continue
                if vendor and cpe["vendor"] != vendor:
                    continue
                r: dict = {}
                if m.get("versionStartIncluding"):
                    r["si"] = m["versionStartIncluding"]
                if m.get("versionStartExcluding"):
                    r["se"] = m["versionStartExcluding"]
                if m.get("versionEndIncluding"):
                    r["ei"] = m["versionEndIncluding"]
                if m.get("versionEndExcluding"):
                    r["ee"] = m["versionEndExcluding"]
                if not r:
                    v = cpe["version"]
                    if v in ("*", "-", ""):
                        continue  # "all versions": cannot be evaluated safely
                    r = {"si": v, "ei": v}
                if r not in ranges:
                    ranges.append(r)
    return ranges


def build_entries(vulns: list[dict], vendor: str | None, product: str, kev_ids: set[str], min_cvss: float) -> list[dict]:
    entries = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id or cve.get("vulnStatus") == "Rejected":
            continue
        score = cvss_of(cve)
        is_kev = cve_id in kev_ids
        if score < min_cvss and not is_kev:
            continue
        ranges = extract_ranges(cve, vendor, product)
        if not ranges:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        match_vendor = vendor or next(
            (parse_cpe23(m["criteria"])["vendor"] for c in cve.get("configurations", []) for n in c.get("nodes", [])
             for m in n.get("cpeMatch", []) if (parse_cpe23(m.get("criteria", "")) or {}).get("product") == product),
            "",
        )
        entries.append({
            "cve": cve_id,
            "vendor": match_vendor,
            "product": product,
            "ranges": ranges,
            "cvss": score,
            "severity": severity_from_cvss(score) if score else "high",
            "kev": is_kev,
            "published": cve.get("published", "")[:10],
            "description": re.sub(r"\s+", " ", desc)[:600],
        })
    return entries


async def _get_json(session: aiohttp.ClientSession, url: str, params: dict | None, delay: float, retries: int = 4):
    for attempt in range(retries):
        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    return await resp.json(content_type=None)
                logger.warning(f"{url} -> HTTP {resp.status} (attempt {attempt + 1})")
        except Exception as exc:
            logger.warning(f"{url} failed: {type(exc).__name__} (attempt {attempt + 1})")
        await asyncio.sleep(delay * (attempt + 2))
    return None


async def fetch_kev(session: aiohttp.ClientSession, url: str = KEV_URL) -> set[str]:
    data = await _get_json(session, url, None, 2.0)
    if not data:
        return set()
    return {v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v}


async def fetch_product(session: aiohttp.ClientSession, spec: str, kev_ids: set[str], min_cvss: float,
                        delay: float, nvd_url: str = NVD_URL) -> list[dict] | None:
    """All qualifying entries for one product spec, or None if NVD could not be reached."""
    if ":" in spec:
        vendor, product = spec.split(":", 1)
        base_params = {"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}"}
    else:
        vendor, product = None, spec
        base_params = {"keywordSearch": product}

    entries: list[dict] = []
    start = 0
    while True:
        data = await _get_json(session, nvd_url, {**base_params, "resultsPerPage": PAGE_SIZE, "startIndex": start}, delay)
        if data is None:
            return None if start == 0 else entries
        vulns = data.get("vulnerabilities", [])
        entries.extend(build_entries(vulns, vendor, product, kev_ids, min_cvss))
        start += len(vulns)
        if not vulns or start >= data.get("totalResults", 0):
            return entries
        await asyncio.sleep(delay)


async def sync(products: list[str], out_path: str, min_cvss: float = 7.0, api_key: str | None = None,
               progress=None, nvd_url: str = NVD_URL, kev_url: str = KEV_URL) -> dict:
    """Fetch everything and write the feed atomically. Returns a per-product report."""
    api_key = api_key or os.environ.get("NVD_API_KEY")
    headers = {"User-Agent": "VulnForge-cve-sync"}
    if api_key:
        headers["apiKey"] = api_key
    delay = DELAY_WITH_KEY if api_key else DELAY_NO_KEY

    report = {"products": {}, "kev_total": 0, "failed": []}
    all_entries: list[dict] = []
    async with aiohttp.ClientSession(headers=headers, timeout=aiohttp.ClientTimeout(total=120)) as session:
        kev_ids = await fetch_kev(session, kev_url)
        report["kev_total"] = len(kev_ids)
        for i, spec in enumerate(products):
            if progress:
                progress(i, len(products), spec)
            entries = await fetch_product(session, spec, kev_ids, min_cvss, delay, nvd_url)
            if entries is None:
                report["failed"].append(spec)
                continue
            report["products"][spec] = len(entries)
            all_entries.extend(entries)
            await asyncio.sleep(delay)

    if not all_entries:
        raise RuntimeError("No CVE data was retrieved; leaving the existing feed untouched.")

    # keep a previous product's data if this run failed for it
    out = Path(out_path)
    if report["failed"] and out.exists():
        try:
            old = json.loads(out.read_text(encoding="utf-8")).get("entries", [])
            failed_products = {s.split(":", 1)[-1] for s in report["failed"]}
            all_entries.extend(e for e in old if e.get("product") in failed_products)
        except (OSError, ValueError):
            pass

    all_entries.sort(key=lambda e: (e["product"], e["cve"]))
    doc = {
        "_note": "Generated by `vulnforge.py cve-update` from NVD API 2.0 and CISA KEV. Do not edit by hand.",
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "min_cvss": min_cvss,
        "entries": all_entries,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    tmp.replace(out)
    report["total_entries"] = len(all_entries)
    return report
