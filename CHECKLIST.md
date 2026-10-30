# VulnForge Feature Checklist

Legend: `[x]` implemented & working · `[~]` partially implemented · `[ ]` planned/backlog

## Batch 0 — Baseline (already existed before this roadmap)

- [x] Click-based CLI with `--scan-type`, `--output`, `--ports`, `--no-auth-check`, `--verbose`
- [x] Interactive authorization confirmation gate (`AuthorizationError` on decline)
- [x] Blocked/reserved IP range enforcement (`authorization.blocked_ranges`)
- [x] Async orchestrator (`core/scanner.py`) running port/web/ssl/plugins concurrently
- [x] Port scanner: nmap wrapper (`-sV -sC -O --script=default,vuln`) + async TCP-connect fallback
- [x] Web scanner: missing security headers, info-disclosure headers, cookie flags
      (Secure/HttpOnly/SameSite), CORS wildcard/credential misconfig, open redirect
      probing, directory listing detection, sensitive path/file exposure probing
- [x] SSL/TLS analyzer: cert expiry/validity, weak protocol detection (SSLv2/3,
      TLS1.0/1.1), weak cipher detection, signature algorithm check, SAN presence
- [x] Plugin system: auto-discovery/loading of `plugin_*.py`, concurrent execution,
      per-plugin timeout
- [x] Sample plugins: DNS recon (SPF/DMARC/zone-transfer/basic subdomain brute force),
      HTTP method/verb tampering
- [x] Reporting: HTML (dark themed), JSON, plain text
- [x] Risk scoring (weighted severity → 0–100)

## Batch 1 — Reporting formats + multi-target scanning

- [x] Markdown report output
- [x] SARIF report output (for GitHub code-scanning / CI gating)
- [x] PDF report output via WeasyPrint (graceful fallback/skip if not installed)
- [x] Multi-target input: comma-separated list, CIDR expansion, `--targets-file`
- [x] Per-target scan loop with combined exit-code logic (worst risk score wins)
- [x] README.md + this checklist

## Batch 2 — CVE matching + web scanner expansion

- [x] `core/cve_matcher.py` — offline CVE lookup against detected service
      product/version (local `data/cve_db.json`, no API key required)
- [x] JWT detection & analysis in web scanner (alg=none, weak/common secrets,
      missing expiry)
- [x] CSP directive scoring (beyond presence-only: flags `unsafe-inline`,
      `unsafe-eval`, wildcard sources)

## Batch 3 — Scan history & persistence

- [x] SQLite-backed scan history (`core/history.py`) — every scan recorded
- [x] `vulnforge.py history` subcommand — list past scans for a target
- [x] `vulnforge.py diff` subcommand — compare two scan IDs, show new/resolved findings

## Batch 4 — CLI / operational UX

- [x] `--dry-run` — show resolved targets + modules without scanning
- [x] `--profile` config presets (quick/balanced/thorough) in `config.json`

## Batch 5 — Bug fixes + manual verification playbook

- [x] **Fixed:** SSL analyzer always reported "No certificate returned" —
      `ssl.getpeercert()`'s parsed-dict form is only populated when
      verification succeeds, but the analyzer deliberately sets
      `verify_mode = CERT_NONE` (so it can inspect self-signed/expired certs
      too). Now parses the raw DER cert via `cryptography.x509` instead,
      independent of verification outcome.
- [x] **Fixed:** nmap port scans silently timed out at 30s (`scan_defaults.timeout`
      was being reused as the whole nmap subprocess timeout) — added a
      dedicated `nmap.timeout` config key (default 300s).
- [x] `core/verification_guide.py` — maps each finding category to concrete
      manual verification steps (curl/openssl/browser devtools/Burp Suite,
      using whichever tool actually fits that category — Burp isn't forced
      onto DNS/raw-TLS checks where it doesn't apply)
- [x] `vulnforge.py verify SCAN_ID` — prints a verification playbook grouped
      by category for every finding in a recorded scan, and saves it as a
      standalone HTML (and optionally PDF) report in the same dark theme as
      scan reports — `-o pdf`, or `--no-file` for console-only
- [x] Every `scan` now auto-generates the verification playbook HTML report
      right after the scan completes (no separate `verify` call needed) —
      opt out per-run with `--no-verify`

## Batch 6 — Governance

- [x] Authorization audit trail export (`core/audit.py`) — a SQLite log
      (separate from scan history) of every authorization-relevant event:
      prompts confirmed/declined,
      blocked-range hits, scan start/completion. `vulnforge.py audit`
      lists or `--export`s it to JSON/CSV for compliance hand-off.

## Batch 7 — Passive recon + fingerprinting

- [x] Passive subdomain enumeration via crt.sh Certificate Transparency logs
      (`plugins/plugin_dns.py`) — resolves a bounded sample to split live vs.
      historical names, flags dev/staging/admin/internal-style hosts. Retries
      on crt.sh 5xx; opt out with `plugins.dns_recon.crtsh: false` (the domain
      name is disclosed to crt.sh, nothing is sent to the target).
- [x] GraphQL endpoint discovery + introspection exposure check
      (`core/web_fingerprint.py`) — harmless `__typename` / `__schema` POSTs only.
- [x] CMS fingerprinting for WordPress/Drupal/Joomla (generator tag, asset
      paths, version files), WordPress REST user enumeration, outdated-core flag.
- [x] CVE public-PoC flag — `public_poc` field in `data/cve_db.json` (curated
      Metasploit module names) surfaced on `cve_match` findings. Absent means
      "not curated", not "no PoC exists".
- [x] Verification playbook steps for the new `graphql` and `cms` categories.

## Batch 8 — Tests + notifications

- [x] `tests/` pytest suite (60 tests): CVE matcher + PoC flag,
      notifier, GraphQL/CMS checks and crt.sh
      parsing against local mock servers. Run: `pytest` (deps in `requirements-dev.txt`).
- [x] Webhook notifications (`core/notifier.py`) - Slack, Discord, or generic
      JSON; https only; URL may come from an env var (`url_env`); only
      risk score, counts and finding titles at/above `min_severity` are sent
      (no evidence); a failing webhook never fails the scan. Off by default.

## Batch 9 — Trends + scheduled scans

- [x] `vulnforge.py trend TARGET` (`core/trends.py`) - risk sparkline and
      direction across recent scans, new/resolved since the previous scan,
      and how many consecutive scans each finding has persisted.
- [x] Recurring scans (`core/scheduler.py`) - `"schedules"` in `config.json`,
      `vulnforge.py schedule list` / `schedule run [--once]`. Intervals like
      `30m`/`6h`/`1d`/`2w` (5 minute floor); last-run state in
      `reports/schedule_state.json`.

## Batch 10 — REST API

- [x] `vulnforge.py serve` (`core/api_server.py`, aiohttp, no new deps) -
      scan history, stored results, per-target trend, and `POST /scans` with
      pollable `/jobs/{id}`.
- [x] Bearer-token auth from `VULNFORGE_API_TOKEN` (16+ chars, constant-time
      compare); refuses to start without it. `/health` is the only open route.
- [x] Localhost-only bind unless `--allow-remote`.
- [x] Hardening: 16 KB body cap, strict target and scan_types validation,
      one in-flight scan per target, concurrency cap, no internals in errors.

## Batch 11 - GitHub Issues ticketing

- [x] `vulnforge.py tickets SCAN_ID [--apply]` (`core/ticketing.py`) - one
      issue per finding at/above `ticketing.min_severity`, deduplicated by a
      stable finding key (state in `reports/ticket_state.json`, key also
      embedded in the issue body); issues are commented on and closed when
      the finding is no longer detected.
- [x] Safe by default: dry run unless `--apply`; token only from the
      environment (`token_env`); evidence excluded from issue bodies unless
      `ticketing.include_evidence` is true; failures are reported and retried
      on the next run rather than lost.

## Batch 12 - Accuracy (false-positive reduction)

Measured on scanme.nmap.org: risk 35 -> 20, 4 false/not-applicable findings removed.

- [x] Findings carry a `confidence` (low / medium / high / confirmed);
      `cve_matcher.min_confidence` (default `medium`) drops weak guesses.
- [x] Sensitive paths need proof (`core/web_validators.py`): content
      validators per path (e.g. `/.env` must contain KEY=value lines, `.git/HEAD`
      must start with `ref:`), a catch-all/soft-404 baseline, and
      intentionally public files (robots.txt, sitemap.xml, security.txt) are
      no longer reported.
- [x] HSTS only flagged on HTTPS; plain-HTTP sites get one accurate
      "HTTPS Not Available" finding. X-Frame-Options skipped when CSP
      `frame-ancestors` is present.
- [x] Stack-trace check uses real signatures (Python/Java/PHP/.NET/Node/SQL),
      not the word "error". Directory listing needs real listing markup.
- [x] nmap vuln scripts: `NOT VULNERABLE`/errors ignored, `VULNERABLE` =
      confirmed, `LIKELY VULNERABLE` = medium, `vulners` lists = low. Severity
      read from the script's own "Risk factor".
- [x] CVE matches on distro-packaged software (Ubuntu/Debian/RHEL...) are
      medium confidence with a "backports possible" note.
- [x] SPF/DMARC only flagged for mail-relevant names; DMARC checks parent
      domains (RFC 7489 fallback).

## Batch 13 - CVE coverage from official feeds

- [x] `vulnforge.py cve-update` (`core/cve_sync.py`) - pulls CVEs from NVD API
      2.0 and the CISA KEV catalog into `data/cve_feed.json` (git-ignored,
      regenerate any time). Keeps CVSS >= `--min-cvss` (default 7.0) plus every
      KEV-listed CVE; stores exact version ranges; skips records it cannot
      evaluate (no version bounds, OS-only CPEs, rejected CVEs). Set
      `NVD_API_KEY` for ~9x faster syncs. 25 default products (SSH, Apache,
      nginx, Tomcat, BIND, Samba, Exim, FTP, Redis, PHP, OpenSSL, MySQL,
      MariaDB, PostgreSQL, Jenkins, ...); add more with `-p vendor:product`
      or `cve_matcher.sync_products`.
- [x] Matcher uses the feed offline: nmap CPE product match (vendor must agree
      for generic names like `http_server`), precise range checks, never
      guesses when the version is unknown.
- [x] CISA KEV CVEs are labeled "exploited in the wild" and stay visible even
      on distro-packaged builds; other version-only matches on distro builds
      are low confidence (hidden by default; the scan summary shows how many).
- [x] Fixed version parsing of letter versions (`1.0.1f` < `1.0.1g`), which
      the old matcher truncated.

## Batch 14 - Removed rules-of-engagement (roe.json)

- [x] Deleted `core/roe.py`, `roe.json.example` and the `authorization.roe`
      config block; scans are no longer scope/time-window restricted.
- [x] Unattended scans: schedules in `config.json` and API requests with the
      bearer token count as the operator's authorization. Blocked reserved-IP
      ranges and the interactive confirm prompt on normal CLI scans remain.
- [x] Audit events renamed `scheduled_scan_started` / `api_scan_started`.

## Backlog — not yet implemented (future batches)

### Scanning engines
- [ ] Active SQLi/XSS/SSRF/command-injection safe probes
- [ ] CMS plugin/theme vulnerability DB (fingerprinting itself is done)
- [ ] Directory/file brute-forcing with external wordlists
- [ ] Cloud storage misconfig scanning (S3/GCS/Azure Blob)
- [ ] Network/host discovery sweep (ARP/ICMP) before per-host scan
- [ ] Default credential checker (opt-in, explicit authorization required)

### Reporting & integration
- [ ] Email report delivery
- [ ] Jira ticketing provider (GitHub Issues is done)

### Scale & orchestration
- [ ] Distributed scanning (queue/worker model)
- [ ] Interactive TUI live dashboard (Textual)

---
*Updated as batches land. Each `[x]` item has corresponding code in the repo —
this file is a tracker, not an aspirational spec.*
