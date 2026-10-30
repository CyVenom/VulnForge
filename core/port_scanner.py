"""
VulnForge Port Scanner Module
Uses nmap (via python-nmap) for service detection, OS fingerprinting,
and vulnerability script scanning. Falls back gracefully if nmap isn't present.
"""
import asyncio
import logging
import shutil
import subprocess
from typing import Any

from .confidence import parse_vuln_script

logger = logging.getLogger("vulnforge.port_scanner")


class PortScanner:
    """Async wrapper around nmap for port/service/vuln scanning."""

    def __init__(self, config: dict):
        self.config = config
        self.nmap_cfg = config.get("nmap", {})
        self.scan_defaults = config.get("scan_defaults", {})
        self._nmap_available = shutil.which("nmap") is not None
        if not self._nmap_available:
            logger.warning("nmap not found in PATH — port scanning will be limited.")

    async def scan(self, target: str) -> dict:
        """Run nmap scan asynchronously and return structured results."""
        if not self._nmap_available:
            return await self._fallback_scan(target)

        ports = self.scan_defaults.get("ports", "1-1024")
        timing = self.nmap_cfg.get("timing", "T4")
        args = self.nmap_cfg.get("arguments", "-sV -sC -O --script=default,vuln")

        cmd = [
            "nmap",
            f"-{timing}",
            "-p", ports,
            "--open",
            "-oX", "-",  # XML output to stdout
            *args.split(),
            target,
        ]

        logger.info(f"Running nmap: {' '.join(cmd)}")

        try:
            loop = asyncio.get_event_loop()
            proc_result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    # nmap.timeout is specifically for the nmap subprocess, which
                    # with -O/--script=vuln across a large port range routinely
                    # takes minutes. scan_defaults.timeout (used elsewhere, e.g.
                    # per-connection timeouts) is deliberately NOT reused here —
                    # that value is too short and caused silent "0 ports found"
                    # timeouts rather than an obvious error.
                    timeout=self.nmap_cfg.get("timeout", 300),
                ),
            )

            if proc_result.returncode not in (0, 6):  # 6 = hosts not up
                logger.error(f"nmap returned code {proc_result.returncode}: {proc_result.stderr}")
                return {"error": proc_result.stderr, "raw": proc_result.stdout}

            return self._parse_nmap_xml(proc_result.stdout, target)

        except subprocess.TimeoutExpired:
            logger.error("nmap scan timed out")
            return {"error": "Scan timed out", "ports": {}}
        except Exception as exc:
            logger.error(f"nmap execution failed: {exc}", exc_info=True)
            return {"error": str(exc), "ports": {}}

    def _parse_nmap_xml(self, xml_output: str, target: str) -> dict:
        """Parse nmap XML output into a structured dict."""
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            return {"raw": xml_output}

        result: dict[str, Any] = {
            "target": target,
            "ports": {},
            "os": {},
            "services": [],
            "host_status": "unknown",
            "script_output": [],
        }

        if not xml_output.strip():
            result["error"] = "Empty nmap output"
            return result

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as exc:
            logger.warning(f"nmap XML parse error: {exc}")
            result["error"] = str(exc)
            result["raw"] = xml_output
            return result

        for host in root.findall("host"):
            # Host status
            status_el = host.find("status")
            if status_el is not None:
                result["host_status"] = status_el.get("state", "unknown")

            # Ports
            ports_el = host.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    portid = port_el.get("portid", "")
                    proto = port_el.get("protocol", "tcp")
                    state_el = port_el.find("state")
                    service_el = port_el.find("service")

                    state = state_el.get("state") if state_el is not None else "unknown"
                    service_name = ""
                    service_version = ""
                    service_product = ""
                    service_extrainfo = ""
                    cpe_list = []

                    if service_el is not None:
                        service_name = service_el.get("name", "")
                        service_version = service_el.get("version", "")
                        service_product = service_el.get("product", "")
                        service_extrainfo = service_el.get("extrainfo", "")
                        for cpe in service_el.findall("cpe"):
                            cpe_list.append(cpe.text or "")

                    # Script output / vulnerabilities
                    scripts = []
                    vulnerabilities = []
                    for script in port_el.findall("script"):
                        script_id = script.get("id", "")
                        script_out = script.get("output", "")
                        scripts.append({"id": script_id, "output": script_out})

                        verdict = parse_vuln_script(script_id, script_out)
                        if verdict:
                            vulnerabilities.append({
                                "id": script_id,
                                "output": script_out[:500],
                                "severity": verdict["severity"],
                                "confidence": verdict["confidence"],
                            })

                    port_key = f"{proto}/{portid}"
                    result["ports"][port_key] = {
                        "port": portid,
                        "proto": proto,
                        "state": state,
                        "service": service_name,
                        "product": service_product,
                        "version": service_version,
                        "extrainfo": service_extrainfo,
                        "cpe": cpe_list,
                        "scripts": scripts,
                        "vulnerabilities": vulnerabilities,
                    }

                    if state == "open" and service_name:
                        result["services"].append(
                            f"{service_product} {service_version}".strip() or service_name
                        )

            # OS detection
            os_el = host.find("os")
            if os_el is not None:
                matches = []
                for osmatch in os_el.findall("osmatch"):
                    matches.append({
                        "name": osmatch.get("name", ""),
                        "accuracy": osmatch.get("accuracy", ""),
                    })
                if matches:
                    result["os"] = {
                        "best_match": matches[0]["name"],
                        "accuracy": matches[0]["accuracy"],
                        "all_matches": matches,
                    }

        logger.info(
            f"nmap parsed: {len(result['ports'])} ports, "
            f"{len(result['services'])} services"
        )
        return result

    async def _fallback_scan(self, target: str) -> dict:
        """Basic TCP connect scan when nmap is unavailable."""
        logger.info(f"Running fallback TCP scan on {target}")
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
        ]
        open_ports: dict[str, Any] = {}

        async def check_port(port: int):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=2
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port, True
            except Exception:
                return port, False

        results = await asyncio.gather(*[check_port(p) for p in common_ports])
        for port, is_open in results:
            if is_open:
                open_ports[f"tcp/{port}"] = {
                    "port": str(port),
                    "proto": "tcp",
                    "state": "open",
                    "service": "unknown",
                    "product": "",
                    "version": "",
                    "cpe": [],
                    "scripts": [],
                    "vulnerabilities": [],
                }

        return {
            "target": target,
            "ports": open_ports,
            "services": [],
            "os": {},
            "host_status": "up" if open_ports else "unknown",
            "note": "nmap not available — basic TCP connect scan only",
        }
