# VulnForge

**Production-grade, async, plugin-extensible security scanner CLI.**

VulnForge orchestrates port/service scanning (nmap), web vulnerability checks,
SSL/TLS analysis, CVE matching, and a plugin system into a single scan with
HTML/JSON/TXT/Markdown/SARIF/PDF reporting — built around an authorization-first
workflow so it refuses to run against targets you haven't confirmed you're
allowed to test.

**[Try the interactive demo](https://vulnforge-demo.vercel.app)** — walk through a scan step by step, built from real
scan output. It runs no scans; the code for it is in
[vulnforge-demo](https://github.com/CyVenom/vulnforge-demo), including a throwaway test server you can scan yourself.

> ⚠️ **Authorized testing only.** Scanning systems without explicit permission
> is illegal in most jurisdictions (CFAA, Computer Misuse Act, etc.). VulnForge
> requires interactive authorization confirmation by default and blocks
> scans against reserved/documentation IP ranges. `--no-auth-check` exists
> only for automated pipelines you already control and have separately
> authorized.

## Features

### Core scanning
- **Port/service scanning** — nmap-backed (`-Pn -sV -sC -O --script=default,vuln`;
  `-Pn` skips host-discovery ping so a target that blocks ICMP isn't
  mistaken for "down" and silently skipped), with a built-in async
  TCP-connect fallback when nmap isn't installed
- **OS fingerprinting** — via nmap `-O`
- **Web vulnerability scanning** — missing security headers, cookie flag issues
  (Secure/HttpOnly/SameSite), CORS misconfiguration, open redirect probing,
  directory listing detection, sensitive file/path exposure (`.git`, `.env`,
  backups, admin panels, actuator endpoints, etc.), server info disclosure,
  JWT weakness detection, CSP directive scoring
- **SSL/TLS analysis** — certificate validity/expiry, weak protocol detection
  (SSLv2/3, TLS 1.0/1.1), weak cipher detection, signature algorithm checks,
  SAN presence
- **CVE matching** — cross-references detected service banners/versions
  against a local CVE dataset (offline-first, no API key required); findings
  note when a public exploit module is known
- **GraphQL & CMS fingerprinting** — endpoint discovery, introspection
  exposure, WordPress/Drupal/Joomla detection with version and user-enumeration checks
- **DNS reconnaissance** — SPF/DMARC checks, zone transfer testing, subdomain
  discovery (brute-force list + passive crt.sh Certificate Transparency lookup)
- **Active safe probes** — canary checks for reflected XSS, SQL injection
  (error- and boolean-based), SSRF (metadata/loopback targets), and OS
  command injection, all with inert payloads (`web.active_probes`)
- **Cloud storage misconfiguration scanning** — public S3/GCS/Azure Blob
  bucket discovery from the target's own name (`plugins/plugin_cloud_storage.py`)
- **Directory/file brute-forcing** — external-wordlist-capable, opt-in
  (`web.dir_bruteforce`), reusing the catch-all/soft-404 baseline filter
- **Default credential checker** — HTTP Basic/FTP, opt-in and requires
  explicit per-run authorization (`--allow-credential-checks`)
- **Host discovery sweep** — portable ping/TCP alive-check before scanning
  a CIDR range or target file (`--host-discovery`)
- **Plugin system** — drop a `plugin_*.py` file in `plugins/` implementing
  `VulnForgePlugin` and it's auto-loaded and run concurrently with everything else

### Scan orchestration
- **Multi-target scanning** — single host, comma-separated list, CIDR range,
  or `--targets-file` with one target per line
- Async parallel execution of all scan modules per target
- Risk scoring (0–100) from weighted severity counts (critical 10, high 7,
  medium 4, low 1). Up to 50 the score is the plain weighted sum; above 50
  extra risk still counts but with diminishing returns, so a scan with 15
  highs and one with 150 no longer both read 100. The CI exit threshold
  (score 40) is unaffected.

### Reporting
- HTML (dark-themed, self-contained), JSON, plain text
- **Markdown** — for pasting into tickets/PRs
- **SARIF** — for GitHub code-scanning / CI integration
- **PDF** — via WeasyPrint (optional dependency; degrades gracefully if missing)

### Safety / governance
- Interactive authorization confirmation before any scan (skippable only with
  `--no-auth-check` for controlled pipelines)
- Blocked IP range enforcement (documentation/reserved ranges) from config.
  Hostnames and URLs are resolved and every address they point to is checked,
  not just literal IPs, so a name that resolves into a blocked range is
  refused (and recorded in the audit trail with the reason). DNS is resolved
  once at check time, so this guards against mistakes, not DNS rebinding by a
  hostile resolver
- All scans logged (`logs/vulnforge.log`) when `authorization.log_all_scans` is set
- Authorization audit trail (`core/audit.py`, separate SQLite DB from scan
  history) recording every confirm/decline, blocked-range hit,
  and scan start/completion — `vulnforge.py audit` to view or `--export` it

## Installation

```bash
git clone <this-repo> VulnForge
cd VulnForge
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

nmap is optional but strongly recommended (`choco install nmap` on Windows,
`apt install nmap` on Debian/Ubuntu). Without it, port scanning falls back to
a basic async TCP-connect sweep of common ports.

PDF reports require `weasyprint`, which in turn needs native GTK/Pango
libraries on Windows — see the
[WeasyPrint install docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows)
if PDF generation fails. Every other report format works without it.

## Usage

```bash
# Single target, all modules, all report formats
python vulnforge.py scanme.nmap.org

# Specific modules + output formats
python vulnforge.py 192.168.1.1 -s port -s ssl -o html -o sarif

# Multiple targets (comma-separated)
python vulnforge.py "scanme.nmap.org,example.com"

# Targets from a file (one per line; CIDR ranges are expanded)
python vulnforge.py --targets-file targets.txt

# CIDR range
python vulnforge.py 192.168.1.0/28

# Skip hosts that don't respond before scanning a range/file
python vulnforge.py 192.168.1.0/24 --host-discovery

# Active default-credential testing (HTTP Basic/FTP) -- requires BOTH this
# flag and "credentials": {"enabled": true} in config.json
python vulnforge.py app.example.com --allow-credential-checks

# Scan profile preset (quick / balanced / thorough — see config.json)
python vulnforge.py scanme.nmap.org --profile quick

# See what would run without actually scanning
python vulnforge.py scanme.nmap.org --dry-run

# Automated pipeline (you've already authorized this out-of-band)
python vulnforge.py https://example.com --no-auth-check -o sarif

# Scan history & diffing
python vulnforge.py history --target scanme.nmap.org
python vulnforge.py diff VF-20260621-231716 VF-20260621-232728

# Manual verification playbook for a recorded scan's findings
python vulnforge.py verify VF-20260621-231716

# Risk trend for a target (sparkline, new/resolved, long-standing findings)
python vulnforge.py trend scanme.nmap.org

# Recurring scans
python vulnforge.py schedule list
python vulnforge.py schedule run --once    # for cron / Task Scheduler
python vulnforge.py schedule run           # foreground loop

# Authorization audit trail
python vulnforge.py audit --target scanme.nmap.org
python vulnforge.py audit --export audit_export.json
```

### Getting broader CVE coverage

The repo ships a small curated CVE set. For wide coverage, build the offline
feed from NVD and CISA KEV (needs internet once; scans stay offline):

```bash
python vulnforge.py cve-update                       # 25 common products, ~5-10 min
python vulnforge.py cve-update -p openbsd:openssh    # just one product
```

A free NVD API key makes it much faster: `set NVD_API_KEY=...` (get one at
nvd.nist.gov/developers/request-an-api-key). Re-run it every few weeks.
The feed is git-ignored and regenerated, not edited by hand.

### How false positives are kept down

Every finding has a `confidence`: `low` (a hint), `medium` (version match on
distro-packaged software, where backported fixes are common), `high`
(deterministic check or content validated) or `confirmed` (a tool reported the
host vulnerable). CVE and nmap-script findings below `cve_matcher.min_confidence`
(default `medium`) are dropped. Exposed files must pass a content check, not
just return HTTP 200. No scanner is free of false positives, so use the
verification playbook for anything that matters.

### Verifying findings manually

Every automated finding can include false positives. **Every `scan` automatically
saves a Verification Playbook report** (same dark theme as the main scan
report) to `reports/<scan_id>-verification.html` right after the scan
completes — concrete manual steps per finding category, the right tool for
each (curl/openssl for headers and TLS, browser DevTools for cookies/CSP,
Burp Suite's Repeater/JWT Editor where Burp is actually the right tool, dig
for DNS, searchsploit for CVE matches). Skip it per-run with `--no-verify`.

You can also (re-)generate it on demand for any past scan:

```bash
python vulnforge.py verify VF-20260621-231716          # console + HTML file
python vulnforge.py verify VF-20260621-231716 -o pdf    # also save as PDF
python vulnforge.py verify VF-20260621-231716 --no-file # console only
```

See `core/verification_guide.py` to add steps for a new finding category.

### GitHub Issues / Jira

```json
"ticketing": {"enabled": true, "provider": "github", "repo": "owner/name",
              "token_env": "GITHUB_TOKEN", "min_severity": "high",
              "labels": ["vulnforge"], "include_evidence": false,
              "jira": {"base_url": "https://yourteam.atlassian.net", "project_key": "SEC",
                       "email_env": "JIRA_EMAIL", "token_env": "JIRA_API_TOKEN"}}
```

```bash
python vulnforge.py tickets VF-20261027-071623                     # dry run (GitHub by default)
python vulnforge.py tickets VF-20261027-071623 --apply              # create / close issues
python vulnforge.py tickets VF-20261027-071623 --provider jira --apply   # same, via Jira
```

Re-running is safe: findings already tracked are skipped, and tickets for
findings that disappeared are closed (a comment on GitHub; a comment plus a
"Done"-like transition on Jira). Evidence is left out of ticket bodies by
default, since trackers are often more visible than scan reports. Jira auth
is email + API token (Atlassian Cloud), both from environment variables
named by `ticketing.jira.email_env`/`token_env`.

### REST API

```bash
export VULNFORGE_API_TOKEN="$(openssl rand -hex 24)"
python vulnforge.py serve                  # http://127.0.0.1:8080
curl -H "Authorization: Bearer $VULNFORGE_API_TOKEN" localhost:8080/scans
curl -H "Authorization: Bearer $VULNFORGE_API_TOKEN" -X POST localhost:8080/scans      -d '{"target": "app.example.com", "scan_types": ["ssl", "web"]}'    # -> 202 + job id
curl -H "Authorization: Bearer $VULNFORGE_API_TOKEN" localhost:8080/jobs/<job_id>
```

Endpoints: `GET /health`, `GET /scans`, `GET /scans/{id}`,
`GET /targets/{target}/trend`, `POST /scans`, `GET /jobs/{id}`. It binds to
localhost only unless you pass `--allow-remote` (then put it behind TLS and a
firewall; the API itself speaks plain HTTP). Whoever holds the token can
start scans, so keep it secret.

### Scheduled scans

Define recurring scans in `config.json`:

```json
"schedules": [
  {"name": "weekly-web", "targets": ["app.example.com"], "every": "7d",
   "scan_types": ["ssl", "web"]}
]
```

There is no authorization prompt on a scheduled run: the targets you list in
the schedule are the authorization. Blocked reserved-IP ranges are still
refused. Pair it with
notifications to get alerted when a scheduled scan finds something new.

### Notifications

Set `notifications.enabled: true` in `config.json` and list webhooks. Keep the
URL out of the file by naming an environment variable:

```json
"notifications": {
  "enabled": true,
  "min_severity": "high",
  "webhooks": [{"name": "team-slack", "type": "slack", "url_env": "VULNFORGE_SLACK_WEBHOOK"}]
}
```

Types: `slack`, `discord`, `generic` (raw JSON summary). Only https URLs are
accepted, and only the risk score, counts and finding titles at or above
`min_severity` are sent; evidence never leaves the machine.

### Active probes, cloud storage, brute-forcing, default credentials

```json
"web": {
  "active_probes": {"enabled": true, "max_params": 8},
  "dir_bruteforce": {"enabled": false, "wordlist_path": null, "max_concurrency": 10, "max_requests": 2000}
},
"plugins": {"cloud_storage": {"enabled": true}},
"credentials": {"enabled": false, "http_basic_pairs": [["admin", "admin"]], "ftp_pairs": [["anonymous", "anonymous"]]}
```

- **Active probes** (XSS/SQLi/SSRF/command injection) run by default as
  part of the normal web scan — every payload is inert (a marker, a single
  quote, a well-known metadata URL, a harmless `echo`), never destructive.
- **Cloud storage** bucket discovery runs by default as a plugin; it only
  talks to the cloud providers' own public endpoints, never the target.
- **Directory brute-forcing** is opt-in (`web.dir_bruteforce.enabled: true`)
  since it's far more request-heavy than the fixed sensitive-path list;
  point `wordlist_path` at any external wordlist (e.g. SecLists) or rely on
  the built-in `data/wordlists/common.txt`.
- **Default credential checks** need **both** `credentials.enabled: true`
  *and* `--allow-credential-checks` on the command line — this is active
  authentication testing, so it never runs from config alone.

### Host discovery

```bash
python vulnforge.py 10.0.0.0/24 --host-discovery --targets-file hosts.txt
```

Before scanning, pings (OS `ping`) and TCP-connects (common ports) every
resolved target; hosts that answer neither are skipped. A portable
best-effort filter, not a replacement for the per-host port scan that follows.

### Live dashboard

```bash
pip install textual
python vulnforge.py tui
```

A read-only, auto-refreshing terminal dashboard over `reports/history.db`:
recent scans across every target, and the selected row's risk trend. Press
`r` to refresh now, `q` to quit. Optional dependency — `tui` gives a clear
error instead of crashing if `textual` isn't installed.

### Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Run `python vulnforge.py --help` for the full option list.

## Configuration

All defaults live in `config.json`: scan ports/timeouts/concurrency, nmap
arguments, masscan settings, web-scanner behavior, SSL check options,
reporting output directory/severity colors, plugin settings, logging, and
authorization (confirmation requirement + blocked IP ranges).

## Project layout

```
vulnforge.py          CLI entry point (Click)
config.json            Default configuration
core/
  scanner.py            Orchestrator — coordinates all modules, builds findings/summary
  port_scanner.py        nmap wrapper + TCP-connect fallback
  web_scanner.py          HTTP vulnerability checks (incl. JWT, CSP scoring)
  web_fingerprint.py      GraphQL discovery/introspection + CMS fingerprinting
  ssl_analyzer.py         TLS/certificate analysis
  cve_matcher.py          Offline CVE lookup against detected service versions
  report_generator.py    HTML/JSON/TXT/Markdown/SARIF/PDF report generation
  plugin_manager.py       Plugin discovery/loading/execution
  target_guard.py         Resolves hosts/URLs and checks them against blocked ranges
  risk.py                 Risk score from severity counts
  history.py              SQLite scan history + diff support
  verification_guide.py   Per-category manual verification steps
  audit.py                Authorization audit trail (SQLite, separate from scan history)
  ticketing.py            GitHub Issues sync (dry-run by default, deduplicated)
  ticketing_jira.py        Jira Cloud sync (same contract as ticketing.py)
  api_server.py           REST API (token auth, localhost-only)
  trends.py               Risk trend + finding persistence from scan history
  scheduler.py            Recurring scans from config.json
  notifier.py             Slack/Discord/generic webhook scan-completion summaries
  active_probes.py        Safe XSS/SQLi/SSRF/command-injection canary checks
  dir_bruteforce.py        Wordlist-based path brute-forcing (opt-in)
  default_creds.py         Default-credential checker (opt-in, HTTP Basic/FTP)
  host_discovery.py        Ping/TCP alive-check sweep ahead of a full scan
  tui.py                   Live Textual dashboard over scan history (optional dep)
plugins/
  plugin_dns.py           DNS recon (SPF/DMARC/zone transfer/subdomains)
  plugin_http_methods.py  HTTP method / verb tampering checks
  plugin_cloud_storage.py  Public S3/GCS/Azure Blob bucket discovery
data/
  cve_db.json             Local curated CVE dataset used by cve_matcher
  wordlists/common.txt    Built-in directory/file brute-force wordlist
reports/               Generated scan reports + audit.db (gitignored)
logs/                  Scan logs (gitignored)
```

## Writing a plugin

```python
from core.plugin_manager import VulnForgePlugin

class MyPlugin(VulnForgePlugin):
    name = "my_plugin"
    description = "What this plugin checks"
    version = "1.0.0"

    async def run(self, target: str, scan_result) -> dict:
        findings = []
        # ... do work, append findings as:
        # {"title": ..., "severity": "critical|high|medium|low|info",
        #  "description": ..., "remediation": ..., "category": ..., "evidence": ...}
        return {"findings": findings, "data": {}}
```

Drop the file in `plugins/` as `plugin_<name>.py` — it's auto-discovered on
the next run. A relative `plugins.dir` is resolved inside the VulnForge
install, never against the folder you ran the command from, because plugin
files are executed. Use an absolute path to load plugins from elsewhere.

## Roadmap

See [CHECKLIST.md](CHECKLIST.md) for the full feature backlog, organized into
batches, with what's implemented vs. planned.

## Legal

VulnForge is for authorized security testing, CTF competitions, and
educational use only. You are responsible for obtaining explicit written
authorization before scanning any system you do not own.

## License

VulnForge's code is released under the [MIT License](LICENSE). The license covers the code only: it does not
give you permission to scan anyone else's systems, and you remain responsible for having that authorization.
The CVE data it uses comes from the NVD and CISA KEV catalog.
