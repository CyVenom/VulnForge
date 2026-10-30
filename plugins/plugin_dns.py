"""
VulnForge Plugin — DNS Reconnaissance
Performs DNS record enumeration and checks for zone transfer, SPF, DMARC, DKIM.
"""
import asyncio
import ipaddress
import logging
import socket
from typing import TYPE_CHECKING

import aiohttp

from core.plugin_manager import VulnForgePlugin

if TYPE_CHECKING:
    from core.scanner import ScanResult

logger = logging.getLogger("vulnforge.plugins.dns")

SUBDOMAINS_TO_CHECK = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "vpn", "dev", "staging",
    "api", "admin", "portal", "remote", "test", "beta", "old",
]

# Subdomain labels that usually should not be internet-facing
SENSITIVE_LABELS = (
    "dev", "staging", "stage", "test", "uat", "qa", "internal", "intranet",
    "admin", "vpn", "jenkins", "gitlab", "git", "jira", "grafana", "kibana",
    "phpmyadmin", "backup", "old", "beta",
)

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CRTSH_MAX_RESOLVE = 100


class DNSReconPlugin(VulnForgePlugin):
    name = "dns_recon"
    description = "DNS record enumeration and security checks (SPF, DMARC, zone transfer)"
    version = "1.0.0"
    author = "VulnForge"

    async def run(self, target: str, scan_result: "ScanResult") -> dict:
        hostname = (
            target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        )

        findings: list[dict] = []
        data: dict = {"hostname": hostname, "records": {}, "subdomains": {}}

        loop = asyncio.get_event_loop()

        # DNS record lookups
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
            try:
                records = await loop.run_in_executor(
                    None, self._lookup, hostname, record_type
                )
                data["records"][record_type] = records
            except Exception:
                data["records"][record_type] = []

        # SPF / DMARC only matter for names that handle mail. A bare web
        # subdomain with no MX record neither sends nor receives mail, and
        # DMARC policy is inherited from the parent (organizational) domain.
        has_mx = bool(data["records"].get("MX"))
        org_level = len(hostname.split(".")) <= 2
        mail_relevant = has_mx or org_level
        mail_severity = "medium" if has_mx else "low"
        no_mail_note = "" if has_mx else " The domain publishes no MX record, so it may not send mail; if so, publish 'v=spf1 -all' to block spoofing."

        txt_records = data["records"].get("TXT", [])
        spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
        if not spf_records and mail_relevant:
            findings.append({
                "title": "No SPF Record Found",
                "severity": mail_severity,
                "description": "Missing SPF record: domain vulnerable to email spoofing." + no_mail_note,
                "remediation": "Add an SPF TXT record to your DNS zone.",
                "category": "dns",
            })

        dmarc_policy_found = False
        for candidate in self._dmarc_candidates(hostname):
            try:
                dmarc = await loop.run_in_executor(None, self._lookup, f"_dmarc.{candidate}", "TXT")
            except Exception:
                dmarc = []
            if any("v=dmarc1" in r.lower() for r in dmarc):
                dmarc_policy_found = True
                data["dmarc_found_at"] = candidate
                break
        if not dmarc_policy_found and mail_relevant:
            findings.append({
                "title": "No DMARC Record Found",
                "severity": mail_severity,
                "description": "Missing DMARC policy (checked this name and its parent domains): phishing/spoofing risk." + no_mail_note,
                "remediation": "Add a _dmarc TXT record with p=reject or p=quarantine.",
                "category": "dns",
            })

        # Subdomain discovery
        async def check_sub(sub: str):
            fqdn = f"{sub}.{hostname}"
            try:
                ip = await loop.run_in_executor(
                    None, socket.gethostbyname, fqdn
                )
                data["subdomains"][fqdn] = ip
            except socket.gaierror:
                pass

        await asyncio.gather(*[check_sub(s) for s in SUBDOMAINS_TO_CHECK])

        if data["subdomains"]:
            logger.info(f"Discovered subdomains: {list(data['subdomains'].keys())}")

        # Passive subdomain enumeration from Certificate Transparency logs
        if self._crtsh_enabled() and not self._is_ip_or_local(hostname):
            await self._crtsh_enumeration(hostname, data, findings, loop)

        # Zone transfer attempt (should fail on properly configured servers)
        try:
            ns_records = data["records"].get("NS", [])
            for ns in ns_records[:2]:
                result_zt = await loop.run_in_executor(
                    None, self._try_zone_transfer, hostname, ns
                )
                if result_zt:
                    findings.append({
                        "title": "DNS Zone Transfer Possible",
                        "severity": "high",
                        "description": f"Zone transfer succeeded from nameserver {ns}.",
                        "remediation": "Restrict zone transfers to authorised slave servers only.",
                        "category": "dns",
                        "evidence": f"AXFR succeeded on {ns}",
                    })
        except Exception as exc:
            logger.debug(f"Zone transfer check error: {exc}")

        return {"findings": findings, "data": data}

    @staticmethod
    def _dmarc_candidates(hostname: str) -> list[str]:
        """hostname, then each parent, stopping at two labels (RFC 7489 fallback)."""
        labels = hostname.split(".")
        return [".".join(labels[i:]) for i in range(0, max(len(labels) - 1, 1))]

    def _crtsh_enabled(self) -> bool:
        return self.config.get("plugins", {}).get("dns_recon", {}).get("crtsh", True)

    @staticmethod
    def _is_ip_or_local(hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return "." not in hostname or hostname.endswith((".local", ".localhost", ".internal"))

    async def _crtsh_enumeration(self, hostname: str, data: dict, findings: list, loop) -> None:
        """
        Query crt.sh (public CT-log search) for certificates issued to
        *.hostname. Passive: nothing is sent to the target itself, but the
        domain name is disclosed to crt.sh. Disable with
        plugins.dns_recon.crtsh = false in config.json.
        """
        entries = None
        last_error = ""
        timeout = aiohttp.ClientTimeout(total=25)
        # crt.sh is frequently overloaded (502/503), so retry briefly
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(CRTSH_URL.format(domain=hostname)) as resp:
                        if resp.status == 200:
                            entries = await resp.json(content_type=None)
                            break
                        last_error = f"HTTP {resp.status}"
            except Exception as exc:
                last_error = str(exc) or type(exc).__name__
            await asyncio.sleep(2 * (attempt + 1))

        if entries is None:
            logger.info(f"crt.sh lookup failed for {hostname}: {last_error}")
            data["crtsh_error"] = last_error
            return

        names: set[str] = set()
        suffix = "." + hostname.lower()
        for entry in entries if isinstance(entries, list) else []:
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(suffix):
                    names.add(name)

        data["crtsh_subdomains"] = sorted(names)
        if not names:
            return

        # Resolve a bounded sample to separate live hosts from historical names
        sample = sorted(names)[:CRTSH_MAX_RESOLVE]
        live: dict[str, str] = {}

        async def resolve(fqdn: str):
            try:
                live[fqdn] = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            except socket.gaierror:
                pass

        await asyncio.gather(*[resolve(n) for n in sample])
        data["crtsh_live"] = live
        for fqdn, ip in live.items():
            data["subdomains"].setdefault(fqdn, ip)

        findings.append({
            "title": f"Subdomains Found in Certificate Transparency Logs ({len(names)})",
            "severity": "info",
            "description": (
                f"crt.sh lists {len(names)} subdomain(s) of {hostname}; "
                f"{len(live)} of the first {len(sample)} resolve today."
            ),
            "remediation": "Review the list for forgotten or unintended hosts and add them to the asset inventory.",
            "category": "dns",
            "evidence": ", ".join(sorted(names)[:15]) + (" ..." if len(names) > 15 else ""),
        })

        risky = sorted(
            n for n in live
            if any(label in n[: -len(suffix)].split(".") for label in SENSITIVE_LABELS)
        )
        if risky:
            findings.append({
                "title": "Potentially Sensitive Subdomains Exposed",
                "severity": "low",
                "description": "Live subdomains named like dev/staging/admin/internal systems are publicly resolvable and advertised in CT logs.",
                "remediation": "Restrict non-production and admin hosts to VPN/allowlisted access, or remove stale DNS records.",
                "category": "dns",
                "evidence": ", ".join(f"{n} ({live[n]})" for n in risky[:10]),
            })

    def _lookup(self, hostname: str, record_type: str) -> list[str]:
        try:
            import dns.resolver  # type: ignore[import]
            answers = dns.resolver.resolve(hostname, record_type, lifetime=5)
            return [str(r) for r in answers]
        except Exception:
            # Fallback for systems without dnspython
            if record_type == "A":
                try:
                    return [socket.gethostbyname(hostname)]
                except Exception:
                    return []
            return []

    def _try_zone_transfer(self, domain: str, ns: str) -> bool:
        try:
            import dns.query  # type: ignore[import]
            import dns.zone  # type: ignore[import]
            zone = dns.zone.from_xfr(dns.query.xfr(ns.rstrip("."), domain, lifetime=5))
            return zone is not None and len(zone.nodes) > 0
        except Exception:
            return False
