#!/usr/bin/env python3
"""
VulnForge -- Production-Grade Security Scanner CLI
Usage: python vulnforge.py [OPTIONS] TARGET
"""
import asyncio
import json
import logging
import sys
from pathlib import Path

# Force UTF-8 output on Windows so Rich's unicode characters render correctly
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import click
from rich.console import Console

console = Console()


def load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        console.print(f"[yellow]Config file {config_path!r} not found — using defaults.[/yellow]")
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def resolve_targets(
    raw_targets: tuple[str, ...],
    targets_file: str | None,
    max_cidr_hosts: int = 256,
) -> list[str]:
    """
    Expand CLI target args + an optional targets file into a flat, deduped
    list of scan targets. Supports:
      - plain hostnames / IPs / URLs
      - comma-separated lists within a single argument
      - CIDR ranges (expanded to individual host IPs, capped at max_cidr_hosts)
      - a --targets-file with one target per line (blank lines / '#' comments skipped)
    """
    import ipaddress

    candidates: list[str] = []
    for arg in raw_targets:
        candidates.extend(part.strip() for part in arg.split(",") if part.strip())

    if targets_file:
        path = Path(targets_file)
        if not path.exists():
            raise click.ClickException(f"Targets file not found: {targets_file}")
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                candidates.append(line)

    resolved: list[str] = []
    for candidate in candidates:
        if "/" in candidate and not candidate.startswith(("http://", "https://")):
            try:
                network = ipaddress.ip_network(candidate, strict=False)
                hosts = list(network.hosts()) or [network.network_address]
                if len(hosts) > max_cidr_hosts:
                    console.print(
                        f"[yellow]Warning:[/yellow] {candidate} expands to {len(hosts)} hosts — "
                        f"truncating to first {max_cidr_hosts}. Raise max_cidr_hosts to scan more."
                    )
                    hosts = hosts[:max_cidr_hosts]
                resolved.extend(str(h) for h in hosts)
                continue
            except ValueError:
                pass  # not a valid CIDR — treat as a plain hostname
        resolved.append(candidate)

    # Dedupe while preserving order
    seen: set[str] = set()
    deduped = []
    for t in resolved:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def build_verification_playbook(findings: list[dict]) -> list[tuple[str, list[dict], dict]]:
    """
    Group findings by category and attach a verification guide to each
    group. Shared by `scan` (auto-verify) and `verify` (on an existing scan).
    """
    from collections import defaultdict
    from core.verification_guide import get_verification_steps

    by_category: dict[str, list] = defaultdict(list)
    for f in findings:
        key = (f.get("category") or f.get("source") or "uncategorized").lower()
        by_category[key].append(f)

    return [(category, items, get_verification_steps(items[0])) for category, items in by_category.items()]


def print_verification_playbook(scan_id: str, target: str, grouped: list[tuple[str, list[dict], dict]]) -> None:
    """Print the full per-finding verification playbook to the console."""
    console.print(
        f"[bold cyan]Verification Playbook — {scan_id}[/bold cyan] (target: {target})\n"
    )
    for category, items, guide in grouped:
        console.print(f"[bold yellow]═══ {category} [/bold yellow]([dim]{len(items)} finding(s)[/dim])")
        for f in items:
            console.print(f"  • [{f.get('severity', 'info').upper()}] {f.get('title')}")
            if f.get("evidence"):
                console.print(f"      [dim]evidence: {f['evidence']}[/dim]")
        console.print(f"  [bold]Tools:[/bold] {', '.join(guide['tools'])}")
        console.print("  [bold]Steps to verify manually:[/bold]")
        for i, step in enumerate(guide["steps"], 1):
            console.print(f"    {i}. {step}")
        console.print()
    console.print(
        "[dim]These are manual verification steps, not an automated confirmation — "
        "VulnForge's findings can include false positives; always confirm before acting "
        "on them, and only test systems you're authorized to test.[/dim]"
    )


class DefaultGroup(click.Group):
    """
    A click.Group that falls back to a default subcommand when the first
    argument isn't a recognized subcommand name, so `vulnforge.py TARGET`
    keeps working exactly as before without requiring `vulnforge.py scan TARGET`.
    """

    def __init__(self, *args, default_cmd_name: str = "scan", **kwargs):
        self.default_cmd_name = default_cmd_name
        super().__init__(*args, **kwargs)

    def resolve_command(self, ctx, args):
        if args and args[0] in self.commands:
            return super().resolve_command(ctx, args)
        cmd = self.get_command(ctx, self.default_cmd_name)
        return self.default_cmd_name, cmd, args


@click.group(cls=DefaultGroup, context_settings={"help_option_names": ["-h", "--help"]})
def cli():
    """VulnForge — Security vulnerability scanner."""


@cli.command("scan", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", nargs=-1, required=False)
@click.option(
    "--targets-file", "-T", default=None,
    help="File with one target per line (hostnames, IPs, URLs, or CIDR ranges).",
)
@click.option(
    "--config", "-c", default="config.json", show_default=True,
    help="Path to config.json",
)
@click.option(
    "--scan-type", "-s", multiple=True,
    type=click.Choice(["port", "service", "os", "vuln", "ssl", "web"], case_sensitive=False),
    help="Scan modules to run (repeatable). Default: all.",
)
@click.option(
    "--output", "-o", multiple=True,
    type=click.Choice(["html", "json", "txt", "markdown", "md", "sarif", "pdf"], case_sensitive=False),
    default=["html", "json", "txt"], show_default=True,
    help="Output report formats.",
)
@click.option(
    "--ports", "-p", default=None,
    help="Port range override (e.g. '1-1000,8080,8443').",
)
@click.option(
    "--profile", type=click.Choice(["quick", "balanced", "thorough"], case_sensitive=False),
    default=None,
    help="Apply a scan profile preset from config.json (overridden by -s/-p if also given).",
)
@click.option(
    "--no-auth-check", is_flag=True, default=False,
    help="Skip the interactive authorization confirmation (use only in automated pipelines you control).",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="Resolve targets and scan modules, print what would run, and exit without scanning.",
)
@click.option(
    "--no-verify", is_flag=True, default=False,
    help="Skip auto-generating the verification playbook report after each scan.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=False,
    help="Enable verbose/debug logging.",
)
def scan_cmd(target, targets_file, config, scan_type, output, ports, profile, no_auth_check, dry_run, no_verify, verbose):
    """
    Run a security scan (this is VulnForge's default command).

    TARGET can be one or more hostnames, IP addresses, URLs, or CIDR ranges
    (space- or comma-separated), or omitted entirely in favor of --targets-file.

    \b
    Examples:
      python vulnforge.py scanme.nmap.org
      python vulnforge.py 192.168.1.1 -s port -s ssl -o html
      python vulnforge.py https://example.com --no-auth-check
      python vulnforge.py "scanme.nmap.org,example.com"
      python vulnforge.py 192.168.1.0/28
      python vulnforge.py --targets-file targets.txt
      python vulnforge.py history --target scanme.nmap.org
      python vulnforge.py diff VF-20260621-231716 VF-20260621-232728
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    cfg = load_config(config)

    if profile:
        preset = cfg.get("profiles", {}).get(profile.lower())
        if not preset:
            raise click.UsageError(f"Profile {profile!r} not found in config.json's 'profiles' section.")
        cfg.setdefault("scan_defaults", {})["ports"] = preset.get("ports", cfg.get("scan_defaults", {}).get("ports"))
        cfg["scan_defaults"]["scan_types"] = preset.get(
            "scan_types", cfg["scan_defaults"].get("scan_types")
        )
        if "nmap_arguments" in preset:
            cfg.setdefault("nmap", {})["arguments"] = preset["nmap_arguments"]
        if "web_sensitive_paths" in preset:
            cfg.setdefault("web", {})["check_sensitive_paths"] = preset["web_sensitive_paths"]
        console.print(f"[cyan]Applied scan profile:[/cyan] {profile}")

    if ports:
        cfg.setdefault("scan_defaults", {})["ports"] = ports

    max_cidr_hosts = cfg.get("scan_defaults", {}).get("max_cidr_hosts", 256)
    targets = resolve_targets(target, targets_file, max_cidr_hosts)

    if not targets:
        raise click.UsageError("No targets given. Pass TARGET(s) or --targets-file.")

    active_types = list(scan_type) or None
    output_formats = [f.lower().replace("markdown", "md") for f in output]

    if dry_run:
        console.print(f"[bold cyan]Dry run — {len(targets)} target(s) resolved:[/bold cyan]")
        for t in targets:
            console.print(f"  [cyan]→[/cyan] {t}")
        console.print(
            f"\n[bold]Scan modules:[/bold] "
            f"{', '.join(active_types) if active_types else 'all (config default)'}"
        )
        console.print(f"[bold]Output formats:[/bold] {', '.join(output_formats)}")
        console.print("[yellow]No scan performed (--dry-run).[/yellow]")
        sys.exit(0)

    # Lazy import to avoid slow startup when --help/--dry-run is used
    from core.scanner import VulnForgeScanner, AuthorizationError

    scanner = VulnForgeScanner(cfg)
    worst_risk = 0
    had_error = False

    try:
        for i, t in enumerate(targets, 1):
            if len(targets) > 1:
                console.print(
                    f"\n[bold magenta]═══ Target {i}/{len(targets)}: {t} ═══[/bold magenta]"
                )
            try:
                result = asyncio.run(
                    scanner.scan(
                        target=t,
                        scan_types=active_types,
                        output_formats=output_formats,
                        skip_auth_check=no_auth_check,
                    )
                )
                worst_risk = max(worst_risk, result.summary.get("risk_score", 0))

                if not no_verify and result.findings:
                    from core.report_generator import ReportGenerator

                    grouped = build_verification_playbook(result.findings)
                    v_paths = asyncio.run(
                        ReportGenerator(cfg).generate_verification_report(
                            result.scan_id, result.target, grouped, ["html"]
                        )
                    )
                    if v_paths:
                        console.print("[bold green]Verification playbook saved:[/bold green]")
                        for p in v_paths:
                            console.print(f"  [cyan]→ {p}[/cyan]")
                        console.print(
                            f"  [dim](run 'vulnforge.py verify {result.scan_id}' for the full "
                            f"console breakdown, or --no-verify to skip this step)[/dim]"
                        )
            except AuthorizationError as exc:
                console.print(f"[red]Authorization denied for {t}: {exc}[/red]")
                had_error = True
            except ValueError as exc:
                # e.g. blocked IP range — don't abort the whole batch
                console.print(f"[red]Skipping {t}: {exc}[/red]")
                had_error = True

        if had_error and worst_risk == 0:
            sys.exit(2)
        sys.exit(0 if worst_risk < 40 else 1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"[bold red]Fatal error:[/bold red] {exc}")
        logging.getLogger("vulnforge").exception("Unhandled exception")
        sys.exit(1)


@cli.command("history", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--target", "-t", default=None, help="Filter history to a specific target.")
@click.option("--limit", "-n", default=20, show_default=True, help="Max number of scans to show.")
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def history_cmd(target, limit, config):
    """List past scans recorded in the local SQLite scan history."""
    from rich.table import Table
    from core.history import ScanHistory

    cfg = load_config(config)
    hist = ScanHistory(cfg)
    rows = hist.list_scans(target=target, limit=limit)

    if not rows:
        console.print("[yellow]No scan history found.[/yellow]")
        return

    table = Table(title="VulnForge Scan History", border_style="cyan")
    table.add_column("Scan ID", style="bold")
    table.add_column("Target")
    table.add_column("Started")
    table.add_column("Duration")
    table.add_column("Risk")
    table.add_column("Findings")
    for r in rows:
        table.add_row(
            r["scan_id"], r["target"], r["start_time"],
            f"{r['duration']}s", str(r["risk_score"]), str(r["total_findings"]),
        )
    console.print(table)


@cli.command("diff", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("old_scan_id")
@click.argument("new_scan_id")
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def diff_cmd(old_scan_id, new_scan_id, config):
    """Compare two recorded scans by scan ID and show new/resolved findings."""
    from core.history import ScanHistory

    cfg = load_config(config)
    hist = ScanHistory(cfg)

    old = hist.get_result(old_scan_id)
    new = hist.get_result(new_scan_id)
    if old is None:
        raise click.ClickException(f"Scan ID not found in history: {old_scan_id}")
    if new is None:
        raise click.ClickException(f"Scan ID not found in history: {new_scan_id}")

    delta = ScanHistory.diff(old, new)

    console.print(f"[bold cyan]Diff: {old_scan_id} → {new_scan_id}[/bold cyan]")
    console.print(f"  Target: {old.get('target')} → {new.get('target')}")
    console.print(
        f"  Risk score: {old.get('summary', {}).get('risk_score', 0)} → "
        f"{new.get('summary', {}).get('risk_score', 0)}"
    )

    console.print(f"\n[bold red]New findings ({len(delta['new'])}):[/bold red]")
    for f in delta["new"]:
        console.print(f"  + [{f.get('severity', 'info').upper()}] {f.get('title')}")

    console.print(f"\n[bold green]Resolved findings ({len(delta['resolved'])}):[/bold green]")
    for f in delta["resolved"]:
        console.print(f"  - [{f.get('severity', 'info').upper()}] {f.get('title')}")

    console.print(f"\n[dim]Unchanged: {len(delta['unchanged'])}[/dim]")


@cli.command("verify", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("scan_id")
@click.option(
    "--output", "-o", multiple=True,
    type=click.Choice(["html", "pdf"], case_sensitive=False),
    default=["html"], show_default=True,
    help="Also write a standalone verification playbook report in these formats.",
)
@click.option(
    "--no-file", is_flag=True, default=False,
    help="Print to console only — don't write a report file.",
)
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def verify_cmd(scan_id, output, no_file, config):
    """
    Print (and save as HTML/PDF) a manual verification playbook for every
    finding in a recorded scan — concrete curl/openssl/browser/Burp Suite
    steps per finding category, so you can confirm or rule out each one by
    hand before reporting it further. This never claims a finding is
    confirmed on its own; it just tells you how to go check.
    """
    from core.history import ScanHistory
    from core.report_generator import ReportGenerator

    cfg = load_config(config)
    hist = ScanHistory(cfg)
    result = hist.get_result(scan_id)
    if result is None:
        raise click.ClickException(
            f"Scan ID not found in history: {scan_id} (run 'vulnforge.py history' to list known scan IDs)"
        )

    findings = result.get("findings", [])
    if not findings:
        console.print(f"[green]No findings recorded for {scan_id} — nothing to verify.[/green]")
        return

    grouped = build_verification_playbook(findings)
    print_verification_playbook(scan_id, result.get("target", ""), grouped)

    if not no_file:
        rg = ReportGenerator(cfg)
        paths = asyncio.run(
            rg.generate_verification_report(scan_id, result.get("target", ""), grouped, list(output))
        )
        if paths:
            console.print("\n[bold green]Verification report saved:[/bold green]")
            for p in paths:
                console.print(f"  [cyan]→ {p}[/cyan]")


@cli.command("audit", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--target", "-t", default=None, help="Filter audit trail to a specific target.")
@click.option("--scan-id", default=None, help="Filter audit trail to a specific scan ID.")
@click.option("--limit", "-n", default=50, show_default=True, help="Max number of entries to show.")
@click.option(
    "--export", "export_path", default=None,
    help="Write the full (unfiltered-by-limit) audit trail to this file instead of printing a table.",
)
@click.option(
    "--format", "fmt", type=click.Choice(["json", "csv"], case_sensitive=False),
    default="json", show_default=True,
    help="Export format (only used with --export).",
)
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def audit_cmd(target, scan_id, limit, export_path, fmt, config):
    """
    View or export the authorization audit trail: every authorization
    prompt, blocked-range hit, and scan
    start/completion event, independent of scan history/findings.
    """
    from rich.table import Table
    from core.audit import AuditTrail

    cfg = load_config(config)
    trail = AuditTrail(cfg)

    if export_path:
        path = trail.export(export_path, fmt=fmt.lower(), target=target)
        console.print(f"[bold green]Audit trail exported:[/bold green] [cyan]{path}[/cyan]")
        return

    entries = trail.list_entries(target=target, scan_id=scan_id, limit=limit)
    if not entries:
        console.print("[yellow]No audit trail entries found.[/yellow]")
        return

    table = Table(title="VulnForge Authorization Audit Trail", border_style="cyan")
    table.add_column("Timestamp", style="bold")
    table.add_column("Event")
    table.add_column("Target")
    table.add_column("Scan ID")
    table.add_column("Actor")
    table.add_column("Detail")
    for e in entries:
        table.add_row(
            e["timestamp"], e["event_type"], e.get("target") or "",
            e.get("scan_id") or "", e.get("actor") or "", (e.get("detail") or "")[:60],
        )
    console.print(table)


@cli.command("trend", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--limit", "-n", default=10, show_default=True, help="How many recent scans to include.")
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def trend_cmd(target, limit, config):
    """Show how a target's risk changed across its recent scans."""
    from rich.table import Table
    from core.history import ScanHistory
    from core.trends import build_trend

    cfg = load_config(config)
    results = ScanHistory(cfg).list_results(target, limit)
    if not results:
        console.print(f"[yellow]No scan history for {target!r} (targets match exactly as scanned).[/yellow]")
        return

    t = build_trend(results)
    colour = {"improving": "green", "worsening": "red"}.get(t["direction"], "yellow")
    console.print(
        f"[bold]{target}[/bold]  risk {t['sparkline']}  "
        f"[{colour}]{t['direction']}[/{colour}]  ({len(results)} scan(s))"
    )

    table = Table(title="Risk by scan", border_style="cyan")
    for col in ("Scan ID", "Started", "Risk", "Findings"):
        table.add_column(col)
    for p in t["points"]:
        table.add_row(p["scan_id"], str(p["start_time"]), str(p["risk_score"]), str(p["total_findings"]))
    console.print(table)

    if len(results) > 1:
        console.print(
            f"Since previous scan: [red]{len(t['new_since_previous'])} new[/red], "
            f"[green]{len(t['resolved_since_previous'])} resolved[/green]"
        )
        for f in t["new_since_previous"][:10]:
            console.print(f"  [red]+[/red] [{f.get('severity', 'info').upper()}] {f.get('title')}")

    long_lived = [p for p in t["persistence"] if p["scans_present"] > 1][:10]
    if long_lived:
        console.print("[bold]Longest-standing findings (consecutive scans present):[/bold]")
        for p in long_lived:
            console.print(f"  {p['scans_present']}x [{p['severity'].upper()}] {p['title']}")


@cli.group("schedule", context_settings={"help_option_names": ["-h", "--help"]})
def schedule_group():
    """Recurring scans defined under "schedules" in config.json."""


@schedule_group.command("list", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def schedule_list_cmd(config):
    """Show configured schedules, when they last ran, and when they are next due."""
    from rich.table import Table
    from core.scheduler import Scheduler

    rows = Scheduler(load_config(config)).describe()
    if not rows:
        console.print("[yellow]No schedules defined (add a \"schedules\" list to config.json).[/yellow]")
        return
    table = Table(title="VulnForge Schedules", border_style="cyan")
    for col in ("Name", "Targets", "Every", "Last run", "Next due", "Problem"):
        table.add_column(col)
    for r in rows:
        table.add_row(r["name"], ", ".join(r["targets"]), str(r["every"]),
                      r["last_run"] or "never", r["next_due"] or "-", r["problem"] or "")
    console.print(table)


@schedule_group.command("run", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--once", is_flag=True, help="Run whatever is due right now, then exit (for cron / Task Scheduler).")
@click.option("--poll", default=60, show_default=True, help="Seconds between checks in loop mode.")
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def schedule_run_cmd(once, poll, config):
    """
    Run due schedules from config.json. There is no authorization prompt:
    the schedule you wrote is the authorization.
    """
    import time
    from core.scanner import VulnForgeScanner
    from core.scheduler import Scheduler

    cfg = load_config(config)
    scheduler = Scheduler(cfg)
    if not scheduler.schedules:
        raise click.UsageError('No schedules defined (add a "schedules" list to config.json).')

    scanner = VulnForgeScanner(cfg)
    try:
        while True:
            for o in asyncio.run(scheduler.run_due(scanner)):
                colour = {"completed": "green", "refused": "yellow"}.get(o["status"], "red")
                extra = o.get("scan_id") or o.get("reason", "")
                console.print(f"[{colour}]{o['schedule']} / {o['target']}: {o['status']}[/{colour}] {extra}")
            if once:
                return
            time.sleep(poll)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scheduler stopped.[/yellow]")


@cli.command("serve", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--host", default="127.0.0.1", show_default=True, help="Interface to bind.")
@click.option("--port", default=8080, show_default=True, help="Port to listen on.")
@click.option("--allow-remote", is_flag=True, help="Permit binding to a non-localhost interface.")
@click.option("--max-concurrent", default=2, show_default=True, help="Max scans running at once.")
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def serve_cmd(host, port, allow_remote, max_concurrent, config):
    """
    Start the REST API. Requires VULNFORGE_API_TOKEN (16+ chars) in the
    environment; whoever holds the token can start scans.
    """
    from aiohttp import web
    from core.api_server import ApiConfigError, check_bind, create_app, load_token
    from core.scanner import VulnForgeScanner

    try:
        check_bind(host, allow_remote)
        token = load_token()
    except ApiConfigError as exc:
        raise click.ClickException(str(exc))

    cfg = load_config(config)
    app = create_app(cfg, VulnForgeScanner(cfg), token, max_concurrent)
    console.print(f"[bold green]VulnForge API listening on http://{host}:{port}[/bold green]")
    web.run_app(app, host=host, port=port, print=None)


@cli.command("tickets", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("scan_id")
@click.option("--apply", is_flag=True, help="Actually create/close GitHub issues (default is a dry run).")
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def tickets_cmd(scan_id, apply, config):
    """
    Sync a recorded scan's findings to GitHub Issues: one issue per finding at
    or above ticketing.min_severity, and close issues whose finding is gone.
    Dry run unless --apply is given.
    """
    from core.history import ScanHistory
    from core.ticketing import GitHubTicketing, TicketingError

    cfg = load_config(config)
    result = ScanHistory(cfg).get_result(scan_id)
    if result is None:
        raise click.ClickException(f"Scan {scan_id!r} not found in history.")

    try:
        report = asyncio.run(
            GitHubTicketing(cfg).sync(scan_id, result["target"], result.get("findings", []), apply=apply)
        )
    except TicketingError as exc:
        raise click.ClickException(str(exc))

    if not apply:
        console.print(f"[bold cyan]Dry run for {scan_id} ({result['target']})[/bold cyan]")
        for t in report["would_create"]:
            console.print(f"  [green]+ would open:[/green] {t}")
        for n in report["would_close"]:
            console.print(f"  [yellow]- would close:[/yellow] #{n}")
        console.print(f"  already tracked: {report['existing']}   (re-run with --apply to send)")
        return
    console.print(f"[bold green]Created:[/bold green] {report['created']}  [bold yellow]Closed:[/bold yellow] {report['closed']}")
    for e in report["errors"]:
        console.print(f"[red]{e}[/red]")
    if report["errors"]:
        sys.exit(1)


@cli.command("cve-update", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--product", "-p", "products", multiple=True,
              help="vendor:product (e.g. openbsd:openssh) or a bare product name. Repeatable. Default: built-in list.")
@click.option("--min-cvss", default=7.0, show_default=True, help="Keep CVEs at or above this CVSS (KEV-listed CVEs are always kept).")
@click.option("--config", "-c", default="config.json", show_default=True, help="Path to config.json")
def cve_update_cmd(products, min_cvss, config):
    """
    Download CVE data from NVD (NIST) and the CISA KEV catalog into
    data/cve_feed.json for offline matching. Set NVD_API_KEY (free from NVD)
    to go about 9x faster; without one expect roughly 5-10 minutes.
    """
    from core.cve_sync import DEFAULT_PRODUCTS, sync

    cfg = load_config(config)
    out = cfg.get("cve_matcher", {}).get("feed_path", "data/cve_feed.json")
    specs = list(products) or cfg.get("cve_matcher", {}).get("sync_products") or DEFAULT_PRODUCTS

    def progress(i, n, spec):
        console.print(f"[cyan]({i + 1}/{n})[/cyan] {spec}")

    try:
        report = asyncio.run(sync(specs, out, min_cvss=min_cvss, progress=progress))
    except RuntimeError as exc:
        raise click.ClickException(str(exc))

    console.print(f"[bold green]Wrote {report['total_entries']} CVE entries to {out}[/bold green]  "
                  f"(CISA KEV catalog: {report['kev_total']} CVEs)")
    for spec, n in report["products"].items():
        console.print(f"  {spec}: {n}" + ("  [yellow](none found; check the vendor:product spelling)[/yellow]" if n == 0 else ""))
    for spec in report["failed"]:
        console.print(f"[red]  {spec}: NVD unreachable, previous data kept[/red]")


if __name__ == "__main__":
    cli()
