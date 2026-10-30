"""
VulnForge Main Scanner Orchestrator
Coordinates all scan modules with async parallel execution.
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table

from .port_scanner import PortScanner
from .web_scanner import WebScanner
from .ssl_analyzer import SSLAnalyzer
from .report_generator import ReportGenerator
from .plugin_manager import PluginManager
from .cve_matcher import CVEMatcher
from .confidence import meets
from .notifier import Notifier
from .history import ScanHistory
from .audit import AuditTrail

logger = logging.getLogger("vulnforge.scanner")
console = Console(highlight=False)


@dataclass
class ScanResult:
    target: str
    scan_id: str
    start_time: str
    end_time: str = ""
    duration: float = 0.0
    authorized: bool = False
    port_scan: dict = field(default_factory=dict)
    web_scan: dict = field(default_factory=dict)
    ssl_analysis: dict = field(default_factory=dict)
    plugin_results: dict = field(default_factory=dict)
    cve_matches: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    hidden_findings: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


class AuthorizationError(Exception):
    pass


class VulnForgeScanner:
    """Main orchestrator for VulnForge scanning operations."""

    BANNER = """
[bold red]
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/bold red]
[bold medium_orchid1]              ✦[/bold medium_orchid1][bold magenta]✦[/bold magenta][bold purple]✦[/bold purple]  [bold purple3] by [/bold purple3][bold medium_orchid1]0x[/bold medium_orchid1][bold magenta]C[/bold magenta][bold medium_purple1]y[/bold medium_purple1][bold purple]b[/bold purple][bold medium_orchid1]e[/bold medium_orchid1][bold magenta]r[/bold magenta][bold medium_purple1]v[/bold medium_purple1][bold purple]e[/bold purple][bold medium_orchid1]n[/bold medium_orchid1][bold magenta]o[/bold magenta][bold medium_purple1]m[/bold medium_purple1]  [bold purple]✦[/bold purple][bold magenta]✦[/bold magenta][bold medium_orchid1]✦[/bold medium_orchid1]
[bold yellow]          Production-Grade Vulnerability & Security Assessment Framework[/bold yellow]
[dim]                        Authorized Security Testing Only[/dim]
"""

    def __init__(self, config: dict):
        self.config = config
        self.port_scanner = PortScanner(config)
        self.web_scanner = WebScanner(config)
        self.ssl_analyzer = SSLAnalyzer(config)
        self.report_generator = ReportGenerator(config)
        self.plugin_manager = PluginManager(config)
        self.cve_matcher = CVEMatcher(config)
        self.notifier = Notifier(config)
        self.history = ScanHistory(config)
        self.audit = AuditTrail(config)
        self._setup_logging()

    def _setup_logging(self):
        log_cfg = self.config.get("logging", {})
        log_file = Path(log_cfg.get("file", "logs/vulnforge.log"))
        log_file.parent.mkdir(parents=True, exist_ok=True)

        level = getattr(logging, log_cfg.get("level", "INFO"))
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(),
            ],
        )

    def print_banner(self):
        console.print(self.BANNER)

    def _check_authorization(self, target: str) -> bool:
        """Confirm user has authorization to scan the target."""
        auth_cfg = self.config.get("authorization", {})

        if not auth_cfg.get("require_confirmation", True):
            return True

        console.print(
            Panel(
                f"[bold yellow]AUTHORIZATION CHECK[/bold yellow]\n\n"
                f"Target: [bold cyan]{target}[/bold cyan]\n\n"
                f"[red]WARNING:[/red] Scanning systems without explicit written permission\n"
                f"is illegal in most jurisdictions (CFAA, Computer Misuse Act, etc.)\n\n"
                f"By proceeding you confirm:\n"
                f"  [green]✓[/green] You own this system, OR\n"
                f"  [green]✓[/green] You have written authorization to test it\n"
                f"  [green]✓[/green] You accept full legal responsibility",
                border_style="yellow",
            )
        )

        response = console.input(
            "[bold yellow]Do you have authorization to scan this target? (yes/no): [/bold yellow]"
        ).strip().lower()

        if response not in ("yes", "y"):
            console.print("[bold red]Scan aborted. No authorization confirmed.[/bold red]")
            logger.warning(f"Scan aborted by user - no authorization confirmed for {target}")
            self.audit.record("authorization_declined", target=target)
            raise AuthorizationError(f"User did not confirm authorization to scan {target}")

        logger.info(f"Authorization confirmed by user for target: {target}")
        self.audit.record("authorization_confirmed", target=target)
        return True

    def _is_blocked(self, target: str) -> bool:
        """Check if target falls within blocked IP ranges."""
        import ipaddress
        blocked = self.config.get("authorization", {}).get("blocked_ranges", [])
        try:
            addr = ipaddress.ip_address(target)
            for blocked_range in blocked:
                if addr in ipaddress.ip_network(blocked_range, strict=False):
                    return True
        except ValueError:
            pass  # It's a hostname, not a raw IP — allow it through
        return False

    async def scan(
        self,
        target: str,
        scan_types: list[str] | None = None,
        output_formats: list[str] | None = None,
        skip_auth_check: bool = False,
    ) -> ScanResult:
        """Run a full security scan against the target."""

        self.print_banner()

        if self._is_blocked(target):
            self.audit.record("blocked_range_denied", target=target)
            raise ValueError(f"Target {target!r} is in a blocked/reserved IP range.")

        if not skip_auth_check:
            self._check_authorization(target)

        scan_id = f"VF-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.audit.record("scan_started", target=target, scan_id=scan_id)
        start = time.time()

        result = ScanResult(
            target=target,
            scan_id=scan_id,
            start_time=datetime.now().isoformat(),
            authorized=True,
        )

        active_types = scan_types or self.config.get("scan_defaults", {}).get(
            "scan_types", ["port", "service", "ssl", "web"]
        )

        console.print(
            Panel(
                f"[bold green]Scan ID:[/bold green] {scan_id}\n"
                f"[bold green]Target:[/bold green]  {target}\n"
                f"[bold green]Modules:[/bold green] {', '.join(active_types)}",
                title="[bold cyan]VulnForge Scan Starting[/bold cyan]",
                border_style="cyan",
            )
        )

        # Load plugins
        await self.plugin_manager.load_plugins()

        tasks: list[asyncio.Task] = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:

            if any(t in active_types for t in ("port", "service", "os", "vuln")):
                task_id = progress.add_task("[cyan]Port / Service Scan...", total=None)
                tasks.append(
                    asyncio.create_task(
                        self._run_port_scan(target, result, progress, task_id)
                    )
                )

            if "ssl" in active_types:
                task_id = progress.add_task("[yellow]SSL / TLS Analysis...", total=None)
                tasks.append(
                    asyncio.create_task(
                        self._run_ssl_analysis(target, result, progress, task_id)
                    )
                )

            if "web" in active_types:
                task_id = progress.add_task("[green]Web Vulnerability Scan...", total=None)
                tasks.append(
                    asyncio.create_task(
                        self._run_web_scan(target, result, progress, task_id)
                    )
                )

            plugin_task_id = progress.add_task("[magenta]Running Plugins...", total=None)
            tasks.append(
                asyncio.create_task(
                    self._run_plugins(target, result, progress, plugin_task_id)
                )
            )

            await asyncio.gather(*tasks, return_exceptions=True)

        result.end_time = datetime.now().isoformat()
        result.duration = round(time.time() - start, 2)
        result.findings = self._aggregate_findings(result)
        result.summary = self._build_summary(result)

        # Generate reports
        formats = output_formats or self.config.get("reporting", {}).get("formats", ["html", "json"])
        report_paths = await self.report_generator.generate(result, formats)

        self._print_summary(result, report_paths)
        self.history.record(result)
        self.audit.record(
            "scan_completed",
            target=target,
            scan_id=scan_id,
            detail={
                "duration": result.duration,
                "findings": len(result.findings),
                "risk_score": result.summary.get("risk_score", 0),
            },
        )

        try:
            for name, ok in await self.notifier.notify_scan_complete(result):
                console.print(f"[{'green' if ok else 'red'}]Notification {name}: {'sent' if ok else 'FAILED'}[/]")
        except Exception as exc:
            logger.warning(f"Notification error: {type(exc).__name__}")

        if self.config.get("authorization", {}).get("log_all_scans", True):
            logger.info(
                f"Scan {scan_id} completed: target={target}, "
                f"duration={result.duration}s, findings={len(result.findings)}"
            )

        return result

    async def _run_port_scan(self, target, result, progress, task_id):
        try:
            result.port_scan = await self.port_scanner.scan(target)
            try:
                result.cve_matches = self.cve_matcher.match_services(result.port_scan)
            except Exception as cve_exc:
                logger.error(f"CVE matching error: {cve_exc}", exc_info=True)
            progress.update(task_id, description="[cyan]Port / Service Scan [green]DONE[/green]")
        except Exception as exc:
            logger.error(f"Port scan error: {exc}", exc_info=True)
            result.port_scan = {"error": str(exc)}
            progress.update(task_id, description="[cyan]Port / Service Scan [red]ERROR[/red]")

    async def _run_ssl_analysis(self, target, result, progress, task_id):
        try:
            result.ssl_analysis = await self.ssl_analyzer.analyze(target)
            progress.update(task_id, description="[yellow]SSL / TLS Analysis [green]DONE[/green]")
        except Exception as exc:
            logger.error(f"SSL analysis error: {exc}", exc_info=True)
            result.ssl_analysis = {"error": str(exc)}
            progress.update(task_id, description="[yellow]SSL / TLS Analysis [red]ERROR[/red]")

    async def _run_web_scan(self, target, result, progress, task_id):
        try:
            result.web_scan = await self.web_scanner.scan(target)
            progress.update(task_id, description="[green]Web Vulnerability Scan [green]DONE[/green]")
        except Exception as exc:
            logger.error(f"Web scan error: {exc}", exc_info=True)
            result.web_scan = {"error": str(exc)}
            progress.update(task_id, description="[green]Web Vulnerability Scan [red]ERROR[/red]")

    async def _run_plugins(self, target, result, progress, task_id):
        try:
            result.plugin_results = await self.plugin_manager.run_all(target, result)
            progress.update(task_id, description="[magenta]Plugins [green]DONE[/green]")
        except Exception as exc:
            logger.error(f"Plugin execution error: {exc}", exc_info=True)
            result.plugin_results = {"error": str(exc)}
            progress.update(task_id, description="[magenta]Plugins [red]ERROR[/red]")

    def _aggregate_findings(self, result: ScanResult) -> list[dict]:
        findings = []

        for port_data in result.port_scan.get("ports", {}).values():
            if port_data.get("vulnerabilities"):
                for vuln in port_data["vulnerabilities"]:
                    findings.append({
                        "source": "port_scan",
                        "severity": vuln.get("severity", "medium"),
                        "title": vuln.get("id", "Unknown CVE"),
                        "description": vuln.get("output", ""),
                        "port": port_data.get("port"),
                        "service": port_data.get("service", ""),
                        "confidence": vuln.get("confidence", "confirmed"),
                    })

        for finding in result.web_scan.get("findings", []):
            findings.append({**finding, "source": "web_scan"})

        for finding in result.ssl_analysis.get("findings", []):
            findings.append({**finding, "source": "ssl_analysis"})

        for finding in result.cve_matches:
            findings.append({**finding, "source": "cve_matcher"})

        for plugin_name, plugin_data in result.plugin_results.items():
            for finding in plugin_data.get("findings", []):
                findings.append({**finding, "source": f"plugin:{plugin_name}"})

        minimum = self.config.get("cve_matcher", {}).get("min_confidence", "medium")
        dropped = [f for f in findings if f.get("source") in ("port_scan", "cve_matcher") and not meets(f.get("confidence"), minimum)]
        if dropped:
            logger.info(f"Dropped {len(dropped)} finding(s) below min_confidence={minimum!r}")
            findings = [f for f in findings if f not in dropped]
        result.hidden_findings = len(dropped)
        for f in findings:
            f.setdefault("confidence", "high")

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))
        return findings

    def _build_summary(self, result: ScanResult) -> dict:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in result.findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        open_ports = [
            p for p, d in result.port_scan.get("ports", {}).items()
            if d.get("state") == "open"
        ]

        return {
            "hidden_low_confidence": result.hidden_findings,
            "total_findings": len(result.findings),
            "severity_counts": severity_counts,
            "open_ports": len(open_ports),
            "services_detected": len(result.port_scan.get("services", [])),
            "web_checks": result.web_scan.get("checks_performed", 0),
            "ssl_issues": len(result.ssl_analysis.get("findings", [])),
            "cve_matches": len(result.cve_matches),
            "plugins_run": len(result.plugin_results),
            "risk_score": self._calculate_risk_score(severity_counts),
        }

    def _calculate_risk_score(self, severity_counts: dict) -> int:
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        raw = sum(weights[s] * c for s, c in severity_counts.items())
        return min(100, raw)

    def _print_summary(self, result: ScanResult, report_paths: list[str]):
        table = Table(title="Scan Summary", border_style="cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", style="cyan")

        s = result.summary
        table.add_row("Scan ID", result.scan_id)
        table.add_row("Target", result.target)
        table.add_row("Duration", f"{result.duration}s")
        table.add_row("Open Ports", str(s.get("open_ports", 0)))
        table.add_row("Total Findings", str(s.get("total_findings", 0)))
        table.add_row("  Critical", f"[red]{s['severity_counts']['critical']}[/red]")
        table.add_row("  High", f"[orange3]{s['severity_counts']['high']}[/orange3]")
        table.add_row("  Medium", f"[yellow]{s['severity_counts']['medium']}[/yellow]")
        table.add_row("  Low", f"[green]{s['severity_counts']['low']}[/green]")
        table.add_row("  Info", f"[blue]{s['severity_counts']['info']}[/blue]")
        if s.get("hidden_low_confidence"):
            table.add_row("Hidden (low confidence)", f"[dim]{s['hidden_low_confidence']} (set cve_matcher.min_confidence to \"low\" to show)[/dim]")
        table.add_row("Risk Score", f"[bold red]{s.get('risk_score', 0)}/100[/bold red]")

        console.print(table)

        if report_paths:
            console.print("\n[bold green]Reports generated:[/bold green]")
            for path in report_paths:
                console.print(f"  [cyan]→ {path}[/cyan]")
