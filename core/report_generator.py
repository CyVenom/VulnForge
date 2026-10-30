"""
VulnForge Report Generator
Produces HTML, JSON, and plain-text reports from scan results.
"""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import ScanResult

logger = logging.getLogger("vulnforge.report_generator")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnForge Report — {scan_id}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f0f0f; color: #e0e0e0; margin: 0; padding: 0; }}
    .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); padding: 40px; border-bottom: 2px solid #e94560; }}
    .header h1 {{ color: #e94560; font-size: 2.5rem; margin: 0 0 8px; }}
    .header .meta {{ color: #aaa; font-size: 0.9rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin: 24px 0; }}
    .stat-card {{ background: #1a1a2e; border-radius: 8px; padding: 20px; text-align: center; border: 1px solid #2a2a4e; }}
    .stat-card .value {{ font-size: 2.5rem; font-weight: bold; }}
    .stat-card .label {{ font-size: 0.8rem; color: #aaa; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
    .critical {{ color: #dc2626; }} .high {{ color: #ea580c; }} .medium {{ color: #d97706; }}
    .low {{ color: #65a30d; }} .info {{ color: #0891b2; }}
    .risk-score {{ font-size: 3rem !important; }}
    .section {{ background: #1a1a2e; border-radius: 8px; padding: 24px; margin: 16px 0; border: 1px solid #2a2a4e; }}
    .section h2 {{ color: #e94560; margin: 0 0 16px; font-size: 1.3rem; border-bottom: 1px solid #2a2a4e; padding-bottom: 8px; }}
    .finding {{ background: #0f0f1a; border-radius: 6px; padding: 16px; margin: 12px 0; border-left: 4px solid #555; }}
    .finding.critical {{ border-left-color: #dc2626; }} .finding.high {{ border-left-color: #ea580c; }}
    .finding.medium {{ border-left-color: #d97706; }} .finding.low {{ border-left-color: #65a30d; }}
    .finding.info {{ border-left-color: #0891b2; }}
    .finding-title {{ font-weight: bold; font-size: 1rem; margin-bottom: 6px; }}
    .finding-meta {{ font-size: 0.8rem; color: #888; margin-bottom: 8px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
    .badge.critical {{ background: #dc2626; color: white; }} .badge.high {{ background: #ea580c; color: white; }}
    .badge.medium {{ background: #d97706; color: black; }} .badge.low {{ background: #65a30d; color: black; }}
    .badge.info {{ background: #0891b2; color: white; }}
    .finding-desc {{ font-size: 0.9rem; color: #ccc; margin: 8px 0; }}
    .finding-remedy {{ font-size: 0.85rem; color: #86efac; }}
    .finding-evidence {{ font-size: 0.8rem; color: #888; font-family: monospace; background: #0a0a0a; padding: 6px 8px; border-radius: 4px; margin-top: 6px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th {{ background: #0f3460; color: #e0e0e0; padding: 10px 12px; text-align: left; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #2a2a4e; }}
    tr:hover td {{ background: #16213e; }}
    .no-findings {{ color: #65a30d; text-align: center; padding: 32px; font-size: 1.1rem; }}
    .footer {{ text-align: center; color: #555; font-size: 0.8rem; padding: 32px; border-top: 1px solid #2a2a4e; margin-top: 32px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>VulnForge Security Report</h1>
    <div class="meta">
      Scan ID: {scan_id} &nbsp;|&nbsp; Target: {target} &nbsp;|&nbsp;
      Generated: {generated_at} &nbsp;|&nbsp; Duration: {duration}s
    </div>
  </div>
  <div class="container">

    <!-- Risk Score + Summary Stats -->
    <div class="summary-grid">
      <div class="stat-card">
        <div class="value risk-score {risk_color}">{risk_score}</div>
        <div class="label">Risk Score / 100</div>
      </div>
      <div class="stat-card">
        <div class="value critical">{critical}</div><div class="label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="value high">{high}</div><div class="label">High</div>
      </div>
      <div class="stat-card">
        <div class="value medium">{medium}</div><div class="label">Medium</div>
      </div>
      <div class="stat-card">
        <div class="value low">{low}</div><div class="label">Low</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:#888">{total}</div><div class="label">Total Findings</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:#7c3aed">{open_ports}</div><div class="label">Open Ports</div>
      </div>
    </div>

    <!-- Findings -->
    <div class="section">
      <h2>Security Findings</h2>
      {findings_html}
    </div>

    <!-- Open Ports -->
    <div class="section">
      <h2>Open Ports &amp; Services</h2>
      {ports_html}
    </div>

    <!-- SSL -->
    <div class="section">
      <h2>SSL / TLS Certificate</h2>
      {ssl_html}
    </div>

  </div>
  <div class="footer">
    Generated by VulnForge &mdash; Authorized Security Testing Only<br>
    Scan ID: {scan_id}
  </div>
</body>
</html>"""


VERIFY_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnForge Verification Playbook — {scan_id}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f0f0f; color: #e0e0e0; margin: 0; padding: 0; }}
    .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); padding: 40px; border-bottom: 2px solid #a855f7; }}
    .header h1 {{ color: #c084fc; font-size: 2.2rem; margin: 0 0 8px; }}
    .header .meta {{ color: #aaa; font-size: 0.9rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
    .intro {{ color: #ccc; font-size: 0.9rem; margin: 16px 0 24px; padding: 12px 16px; background: #1a1a2e; border-left: 4px solid #a855f7; border-radius: 4px; }}
    .critical {{ color: #dc2626; }} .high {{ color: #ea580c; }} .medium {{ color: #d97706; }}
    .low {{ color: #65a30d; }} .info {{ color: #0891b2; }}
    .section {{ background: #1a1a2e; border-radius: 8px; padding: 24px; margin: 20px 0; border: 1px solid #2a2a4e; }}
    .section h2 {{ color: #c084fc; margin: 0 0 4px; font-size: 1.2rem; text-transform: capitalize; }}
    .section .count {{ color: #888; font-size: 0.85rem; font-weight: normal; }}
    .finding {{ background: #0f0f1a; border-radius: 6px; padding: 16px; margin: 12px 0; border-left: 4px solid #555; }}
    .finding.critical {{ border-left-color: #dc2626; }} .finding.high {{ border-left-color: #ea580c; }}
    .finding.medium {{ border-left-color: #d97706; }} .finding.low {{ border-left-color: #65a30d; }}
    .finding.info {{ border-left-color: #0891b2; }}
    .finding-title {{ font-weight: bold; font-size: 1rem; margin-bottom: 6px; }}
    .finding-meta {{ font-size: 0.8rem; color: #888; margin-bottom: 8px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
    .badge.critical {{ background: #dc2626; color: white; }} .badge.high {{ background: #ea580c; color: white; }}
    .badge.medium {{ background: #d97706; color: black; }} .badge.low {{ background: #65a30d; color: black; }}
    .badge.info {{ background: #0891b2; color: white; }}
    .finding-desc {{ font-size: 0.9rem; color: #ccc; margin: 8px 0; }}
    .finding-remedy {{ font-size: 0.85rem; color: #86efac; }}
    .finding-evidence {{ font-size: 0.8rem; color: #888; font-family: monospace; background: #0a0a0a; padding: 6px 8px; border-radius: 4px; margin-top: 6px; word-break: break-all; }}
    .verify-box {{ background: #1e1030; border: 1px solid #6b21a8; border-radius: 6px; padding: 16px; margin-top: 16px; }}
    .verify-tools {{ color: #e9d5ff; font-size: 0.9rem; margin-bottom: 10px; }}
    .verify-tools strong {{ color: #c084fc; }}
    .verify-steps strong {{ color: #c084fc; }}
    .verify-steps ol {{ margin: 8px 0 0; padding-left: 20px; }}
    .verify-steps li {{ color: #ddd; font-size: 0.88rem; margin: 8px 0; line-height: 1.5; }}
    .verify-steps code, .verify-steps li {{ font-family: 'Segoe UI', system-ui, sans-serif; }}
    .verify-steps li::marker {{ color: #c084fc; font-weight: bold; }}
    .footer {{ text-align: center; color: #555; font-size: 0.8rem; padding: 32px; border-top: 1px solid #2a2a4e; margin-top: 32px; }}
    .disclaimer {{ text-align: center; color: #888; font-size: 0.8rem; padding: 16px; font-style: italic; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🔍 VulnForge Verification Playbook</h1>
    <div class="meta">
      Scan ID: {scan_id} &nbsp;|&nbsp; Target: {target} &nbsp;|&nbsp; Generated: {generated_at}
    </div>
  </div>
  <div class="container">
    <div class="intro">
      Manual verification steps for every finding in this scan — the right tool per category
      (curl/openssl, browser DevTools, Burp Suite's Repeater/JWT Editor, dig, searchsploit).
      These confirm or rule out a finding; they are not an automated proof on their own.
    </div>
    {sections_html}
  </div>
  <div class="disclaimer">
    Only test systems you are authorized to test. Findings may include false positives — verify before acting on them.
  </div>
  <div class="footer">
    Generated by VulnForge &mdash; Authorized Security Testing Only<br>
    Scan ID: {scan_id}
  </div>
</body>
</html>"""


class ReportGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.report_cfg = config.get("reporting", {})
        self.output_dir = Path(self.report_cfg.get("output_dir", "reports"))

    async def generate(self, result: "ScanResult", formats: list[str]) -> list[str]:
        """Generate reports in requested formats. Returns list of file paths."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        paths = []

        for fmt in formats:
            try:
                if fmt == "html":
                    path = await self._generate_html(result)
                elif fmt == "json":
                    path = await self._generate_json(result)
                elif fmt in ("txt", "text"):
                    path = await self._generate_txt(result)
                elif fmt in ("md", "markdown"):
                    path = await self._generate_markdown(result)
                elif fmt == "sarif":
                    path = await self._generate_sarif(result)
                elif fmt == "pdf":
                    path = await self._generate_pdf(result)
                    if path is None:
                        continue
                else:
                    logger.warning(f"Unknown report format: {fmt}")
                    continue
                paths.append(str(path))
                logger.info(f"Report generated: {path}")
            except Exception as exc:
                logger.error(f"Failed to generate {fmt} report: {exc}", exc_info=True)

        return paths

    async def _generate_json(self, result: "ScanResult") -> Path:
        path = self.output_dir / f"{result.scan_id}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        return path

    async def _generate_txt(self, result: "ScanResult") -> Path:
        path = self.output_dir / f"{result.scan_id}.txt"
        lines = [
            "=" * 70,
            f"  VULNFORGE SECURITY REPORT",
            f"  Scan ID : {result.scan_id}",
            f"  Target  : {result.target}",
            f"  Started : {result.start_time}",
            f"  Duration: {result.duration}s",
            "=" * 70,
            "",
            f"RISK SCORE: {result.summary.get('risk_score', 0)}/100",
            "",
            "FINDINGS SUMMARY:",
        ]
        sev = result.summary.get("severity_counts", {})
        for level in ("critical", "high", "medium", "low", "info"):
            lines.append(f"  {level.upper():10s}: {sev.get(level, 0)}")

        lines += ["", "=" * 70, "FINDINGS:", ""]
        if not result.findings:
            lines.append("  No significant findings.")
        else:
            for i, f in enumerate(result.findings, 1):
                lines += [
                    f"[{i}] [{f.get('severity', 'info').upper()}] {f.get('title', 'N/A')}",
                    f"    Source : {f.get('source', '')}",
                    f"    Desc   : {f.get('description', '')}",
                    f"    Fix    : {f.get('remediation', '')}",
                    "",
                ]

        lines += ["=" * 70, "END OF REPORT"]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    async def _generate_html(self, result: "ScanResult") -> Path:
        path = self.output_dir / f"{result.scan_id}.html"
        html = self._build_html(result)
        path.write_text(html, encoding="utf-8")
        return path

    def _build_html(self, result: "ScanResult") -> str:
        # Findings HTML
        if not result.findings:
            findings_html = '<div class="no-findings">✓ No significant findings detected.</div>'
        else:
            parts = []
            for f in result.findings:
                sev = f.get("severity", "info").lower()
                evidence_html = ""
                if f.get("evidence"):
                    evidence_html = f'<div class="finding-evidence">{f["evidence"]}</div>'
                parts.append(f"""
<div class="finding {sev}">
  <div class="finding-title">
    <span class="badge {sev}">{sev}</span>
    &nbsp;{f.get("title", "N/A")}
  </div>
  <div class="finding-meta">Source: {f.get("source", "")} &nbsp;|&nbsp; Category: {f.get("category", "")}</div>
  <div class="finding-desc">{f.get("description", "")}</div>
  <div class="finding-remedy">Remediation: {f.get("remediation", "")}</div>
  {evidence_html}
</div>""")
            findings_html = "\n".join(parts)

        # Ports HTML
        ports = result.port_scan.get("ports", {})
        if not ports:
            ports_html = "<p style='color:#888'>No open ports detected or port scan not run.</p>"
        else:
            rows = ""
            for key, pd in ports.items():
                if pd.get("state") == "open":
                    rows += (
                        f"<tr><td>{pd.get('port')}</td><td>{pd.get('proto')}</td>"
                        f"<td>{pd.get('service')}</td><td>{pd.get('product','')} {pd.get('version','')}</td>"
                        f"<td>{', '.join(pd.get('cpe', []))}</td></tr>"
                    )
            ports_html = f"""<table>
<thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Version</th><th>CPE</th></tr></thead>
<tbody>{rows or '<tr><td colspan="5" style="color:#888">No open ports</td></tr>'}</tbody>
</table>"""

        # SSL HTML
        ssl = result.ssl_analysis.get("certificate", {})
        if ssl and "error" not in ssl:
            days = ssl.get("days_remaining")
            days_str = f"{days} days" if days is not None else "N/A"
            color = "#dc2626" if (days is not None and days < 0) else (
                "#d97706" if (days is not None and days < 30) else "#65a30d"
            )
            ssl_html = f"""<table>
<tbody>
<tr><td>Subject CN</td><td>{ssl.get("subject", {}).get("commonName", "N/A")}</td></tr>
<tr><td>Issuer</td><td>{ssl.get("issuer", {}).get("organizationName", "N/A")}</td></tr>
<tr><td>Valid From</td><td>{ssl.get("not_before", "N/A")}</td></tr>
<tr><td>Expires</td><td>{ssl.get("not_after", "N/A")}</td></tr>
<tr><td>Days Remaining</td><td style="color:{color};font-weight:bold">{days_str}</td></tr>
<tr><td>TLS Version</td><td>{ssl.get("tls_version", "N/A")}</td></tr>
<tr><td>Cipher Suite</td><td>{ssl.get("cipher_suite", "N/A")}</td></tr>
<tr><td>SANs</td><td>{', '.join(ssl.get("san", []))}</td></tr>
</tbody></table>"""
        elif ssl and "error" in ssl:
            ssl_html = f'<p style="color:#ea580c">SSL analysis error: {ssl["error"]}</p>'
        else:
            ssl_html = '<p style="color:#888">SSL analysis not performed.</p>'

        sev = result.summary.get("severity_counts", {})
        risk = result.summary.get("risk_score", 0)
        risk_color = "critical" if risk >= 70 else ("high" if risk >= 40 else ("medium" if risk >= 20 else "low"))

        html = HTML_TEMPLATE.format(
            scan_id=result.scan_id,
            target=result.target,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            duration=result.duration,
            risk_score=risk,
            risk_color=risk_color,
            critical=sev.get("critical", 0),
            high=sev.get("high", 0),
            medium=sev.get("medium", 0),
            low=sev.get("low", 0),
            total=result.summary.get("total_findings", 0),
            open_ports=result.summary.get("open_ports", 0),
            findings_html=findings_html,
            ports_html=ports_html,
            ssl_html=ssl_html,
        )

        return html

    async def _generate_markdown(self, result: "ScanResult") -> Path:
        """Produce a Markdown report — handy for pasting into tickets/PRs."""
        path = self.output_dir / f"{result.scan_id}.md"
        s = result.summary
        sev = s.get("severity_counts", {})

        lines = [
            f"# VulnForge Security Report — `{result.scan_id}`",
            "",
            f"| | |",
            f"|---|---|",
            f"| **Target** | {result.target} |",
            f"| **Started** | {result.start_time} |",
            f"| **Duration** | {result.duration}s |",
            f"| **Risk Score** | **{s.get('risk_score', 0)}/100** |",
            f"| **Open Ports** | {s.get('open_ports', 0)} |",
            f"| **Total Findings** | {s.get('total_findings', 0)} |",
            "",
            "## Severity Breakdown",
            "",
            "| Critical | High | Medium | Low | Info |",
            "|---|---|---|---|---|",
            (
                f"| {sev.get('critical', 0)} | {sev.get('high', 0)} | "
                f"{sev.get('medium', 0)} | {sev.get('low', 0)} | {sev.get('info', 0)} |"
            ),
            "",
            "## Findings",
            "",
        ]

        if not result.findings:
            lines.append("✅ No significant findings detected.")
        else:
            for i, f in enumerate(result.findings, 1):
                sev_badge = f.get("severity", "info").upper()
                lines += [
                    f"### {i}. [{sev_badge}] {f.get('title', 'N/A')}",
                    "",
                    f"- **Source:** {f.get('source', '')}",
                    f"- **Category:** {f.get('category', '')}",
                    f"- **Description:** {f.get('description', '')}",
                    f"- **Remediation:** {f.get('remediation', '')}",
                ]
                if f.get("evidence"):
                    lines.append(f"- **Evidence:** `{f['evidence']}`")
                lines.append("")

        lines += [
            "## Open Ports & Services",
            "",
        ]
        ports = result.port_scan.get("ports", {})
        open_ports = {k: v for k, v in ports.items() if v.get("state") == "open"}
        if not open_ports:
            lines.append("No open ports detected or port scan not run.")
        else:
            lines += ["| Port | Proto | Service | Version |", "|---|---|---|---|"]
            for pd in open_ports.values():
                lines.append(
                    f"| {pd.get('port')} | {pd.get('proto')} | {pd.get('service')} | "
                    f"{pd.get('product', '')} {pd.get('version', '')} |"
                )

        lines += ["", "---", "*Generated by VulnForge — Authorized Security Testing Only*"]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    async def _generate_sarif(self, result: "ScanResult") -> Path:
        """
        Produce a SARIF 2.1.0 report for GitHub code-scanning / CI gating.
        Findings are mapped as results against a synthetic 'network target'
        artifact since this is a runtime scan, not static analysis.
        """
        path = self.output_dir / f"{result.scan_id}.sarif"

        severity_to_level = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        rules = {}
        sarif_results = []

        for f in result.findings:
            sev = f.get("severity", "info").lower()
            rule_id = f.get("category") or f.get("source") or "vulnforge-finding"
            rule_id = str(rule_id).replace(" ", "-")

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.get("title", rule_id),
                    "shortDescription": {"text": f.get("title", rule_id)},
                    "fullDescription": {"text": f.get("description", "")},
                    "defaultConfiguration": {"level": severity_to_level.get(sev, "warning")},
                    "properties": {"security-severity": self._severity_score(sev)},
                }

            sarif_results.append({
                "ruleId": rule_id,
                "level": severity_to_level.get(sev, "warning"),
                "message": {
                    "text": (
                        f"{f.get('title', 'Finding')} — {f.get('description', '')} "
                        f"(remediation: {f.get('remediation', 'n/a')})"
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": result.target},
                    }
                }],
                "properties": {
                    "severity": sev,
                    "source": f.get("source", ""),
                    "evidence": f.get("evidence", ""),
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnForge",
                        "informationUri": "https://github.com/",
                        "version": self.config.get("version", "1.0.0"),
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "scan_id": result.scan_id,
                    "target": result.target,
                    "risk_score": result.summary.get("risk_score", 0),
                },
            }],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2, default=str)
        return path

    @staticmethod
    def _severity_score(sev: str) -> str:
        """Map severity to a SARIF security-severity score string (0.0-10.0)."""
        return {
            "critical": "9.5",
            "high": "7.5",
            "medium": "5.0",
            "low": "2.5",
            "info": "0.0",
        }.get(sev, "5.0")

    async def _generate_pdf(self, result: "ScanResult") -> "Path | None":
        """
        Render the same HTML report to PDF via WeasyPrint. Returns None (and
        logs a warning) if weasyprint or its native dependencies aren't
        available, so PDF is purely opt-in and never blocks other formats.
        """
        try:
            from weasyprint import HTML  # type: ignore[import]
        except Exception as exc:
            logger.warning(
                f"PDF report skipped — weasyprint unavailable ({exc}). "
                f"Install it and its native deps, or drop 'pdf' from --output."
            )
            return None

        path = self.output_dir / f"{result.scan_id}.pdf"
        html = self._build_html(result)
        try:
            HTML(string=html).write_pdf(str(path))
        except Exception as exc:
            logger.error(f"PDF generation failed: {exc}", exc_info=True)
            return None
        return path

    async def generate_verification_report(
        self,
        scan_id: str,
        target: str,
        grouped: list[tuple[str, list[dict], dict]],
        formats: list[str],
    ) -> list[str]:
        """
        Build a standalone verification playbook report (same dark theme as
        the main scan report): every finding plus the concrete manual/Burp
        Suite steps to confirm it, grouped by category.

        `grouped` is [(category, [finding, ...], {"tools": [...], "steps": [...]}), ...]
        as produced by `vulnforge.py verify`.
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        html = self._build_verification_html(scan_id, target, grouped)
        paths = []

        for fmt in formats:
            try:
                if fmt == "html":
                    path = self.output_dir / f"{scan_id}-verification.html"
                    path.write_text(html, encoding="utf-8")
                elif fmt == "pdf":
                    try:
                        from weasyprint import HTML  # type: ignore[import]
                    except Exception as exc:
                        logger.warning(
                            f"PDF verification report skipped — weasyprint unavailable ({exc})."
                        )
                        continue
                    path = self.output_dir / f"{scan_id}-verification.pdf"
                    HTML(string=html).write_pdf(str(path))
                else:
                    logger.warning(f"Unknown verification report format: {fmt}")
                    continue
                paths.append(str(path))
                logger.info(f"Verification report generated: {path}")
            except Exception as exc:
                logger.error(f"Failed to generate verification {fmt} report: {exc}", exc_info=True)

        return paths

    def _build_verification_html(
        self, scan_id: str, target: str, grouped: list[tuple[str, list[dict], dict]]
    ) -> str:
        sections = []
        for category, items, guide in grouped:
            findings_html = []
            for f in items:
                sev = f.get("severity", "info").lower()
                evidence_html = ""
                if f.get("evidence"):
                    evidence_html = f'<div class="finding-evidence">{f["evidence"]}</div>'
                findings_html.append(f"""
<div class="finding {sev}">
  <div class="finding-title">
    <span class="badge {sev}">{sev}</span>
    &nbsp;{f.get("title", "N/A")}
  </div>
  <div class="finding-meta">Source: {f.get("source", "")} &nbsp;|&nbsp; Category: {f.get("category", "")}</div>
  <div class="finding-desc">{f.get("description", "")}</div>
  <div class="finding-remedy">Remediation: {f.get("remediation", "")}</div>
  {evidence_html}
</div>""")

            steps_html = "".join(f"<li>{step}</li>" for step in guide.get("steps", []))
            tools_html = ", ".join(guide.get("tools", []))

            sections.append(f"""
<div class="section">
  <h2>{category} <span class="count">({len(items)} finding(s))</span></h2>
  {"".join(findings_html)}
  <div class="verify-box">
    <div class="verify-tools"><strong>Tools:</strong> {tools_html}</div>
    <div class="verify-steps">
      <strong>Steps to verify manually:</strong>
      <ol>{steps_html}</ol>
    </div>
  </div>
</div>""")

        return VERIFY_HTML_TEMPLATE.format(
            scan_id=scan_id,
            target=target,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            sections_html="\n".join(sections),
        )
