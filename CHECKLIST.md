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

## Batch 15 - Active safe probes (XSS / SQLi / SSRF / command injection)

- [x] `core/active_probes.py` - canary checks run against common query
      parameters on the base URL: reflected-input (potential XSS, unescaped
      marker reflection), SQL injection (error-based signature match, plus a
      lower-confidence boolean-based length/status diff), SSRF (well-known
      metadata/loopback targets, flagged only if their own response
      signature is leaked back), and OS command injection (harmless
      `echo <random-token>`, flagged only if the token comes back). Every
      payload is inert - no real exploitation, no destructive commands.
- [x] Wired into `web_scanner.py`'s normal scan pass; opt out with
      `web.active_probes.enabled: false`. New finding categories (`xss`,
      `sqli`, `ssrf`, `command_injection`) each have verification-playbook
      steps in `core/verification_guide.py`.
- [x] `tests/test_active_probes.py` - mock-server tests for all four probe types.

## Batch 16 - Cloud storage misconfiguration scanning

- [x] `plugins/plugin_cloud_storage.py` - derives candidate bucket/container
      names from the target's hostname (plus common suffixes like
      `-backup`/`-dev`/`-static`) and checks S3, Google Cloud Storage, and
      Azure Blob's own public endpoints for anonymous listing access.
      Never touches the target itself; read-only (list/read check), no
      write/delete attempted. Opt out with `plugins.cloud_storage.enabled: false`.
- [x] `cloud_storage` verification-playbook category (AWS/gsutil/az CLI cross-check).

## Batch 17 - Directory/file brute-forcing with external wordlists

- [x] `core/dir_bruteforce.py` - probes a wordlist of paths (bounded by
      `max_concurrency`/`max_requests`), reusing the same soft-404/catch-all
      baseline filter as the sensitive-path check so SPA routers that
      answer 200 for everything don't flood the report. Accepts an external
      wordlist via `web.dir_bruteforce.wordlist_path` (e.g. SecLists) or
      falls back to the small built-in `data/wordlists/common.txt`.
- [x] Off by default (`web.dir_bruteforce.enabled: false`) - noisier and
      more request-heavy than the fixed sensitive-path list, so it's opt-in.
- [x] `tests/test_dir_bruteforce.py`.

## Batch 18 - Default credential checker (opt-in, explicit authorization)

- [x] `core/default_creds.py` - tries a short curated list of default/common
      credential pairs against HTTP Basic Auth and FTP. Requires **both**
      `credentials.enabled: true` in config.json **and** the new
      `--allow-credential-checks` CLI flag on that specific run - neither
      alone starts it, so a credential attempt is never a surprise. A
      successful login is reported at `critical` severity; nothing further
      is read or written through that session.
- [x] `tests/test_default_creds.py`.

## Batch 19 - Network/host discovery sweep before per-host scan

- [x] `core/host_discovery.py` - a portable alive-check (OS `ping` +
      TCP-connect against common ports) ahead of a full scan, so time
      isn't spent running every module against hosts that never answer.
- [x] `--host-discovery` flag on `scan_cmd` - sweeps all resolved targets
      (most useful with a CIDR range or `--targets-file`) and skips any
      that don't respond, before scanning the rest.
- [x] `tests/test_host_discovery.py`.

## Batch 20 - Jira ticketing provider

- [x] `core/ticketing_jira.py` - same dry-run-by-default, dedup-by-key,
      evidence-excluded-unless-opted-in design as the GitHub Issues sync,
      targeting Jira Cloud's REST API (basic auth via email + API token,
      both from environment variables). Closing posts a comment and walks
      the issue's own transition list for one matching
      `ticketing.jira.done_transition_names`.
- [x] `vulnforge.py tickets --provider jira|github` (default: `github`, or
      `ticketing.provider` in config.json).

## Batch 21 - Interactive TUI dashboard

- [x] `core/tui.py` (Textual, optional dependency) - a live-refreshing
      terminal dashboard over `reports/history.db`: a table of recent scans
      across all targets, and the selected row's risk trend
      (sparkline/direction/new-resolved-since-previous). Read-only.
- [x] `vulnforge.py tui` - degrades to a clear error message (not a crash)
      if `textual` isn't installed; `pip install textual` to enable it.

## Batch 22 - Hardening and score fixes

- [x] **Fixed:** the blocked-range check only inspected targets that were
      literal IPs, so a hostname or URL resolving into a blocked range
      (for example `169.254.169.254`) was allowed. New `core/target_guard.py`
      extracts the host from names, `host:port`, URLs and bracketed IPv6,
      resolves it, and checks every address (including IPv4-mapped IPv6).
      The audit trail now records why a target was refused. An invalid entry
      in `authorization.blocked_ranges` raises instead of being skipped.
- [x] **Fixed:** a relative `plugins.dir` was resolved against the current
      working directory, so running VulnForge inside any folder containing a
      `plugins/` directory executed that folder's code. It is now resolved
      against the install directory; absolute paths still work.
- [x] **Changed:** risk score (`core/risk.py`) is unchanged up to 50 and
      uses diminishing returns above it, instead of a flat cap at 100 that
      made 15 highs and 150 highs identical. Scans scoring above 50 now read
      lower than before (for example 10 highs: 70 -> 59); the CI threshold at
      40 is unaffected. Scores already stored in history are not rewritten, so
      trends that span this change will show a step for scans above 50.
- [x] **Fixed:** a finding with a severity label the scorer did not know
      raised `KeyError`; unknown labels now count as zero.
- [x] `pytest.ini` sets `asyncio_default_fixture_loop_scope` (silences the
      pytest-asyncio deprecation warning). 40 new tests (118 total).

## Backlog — not yet implemented (future batches)

### Scanning engines
- [ ] CMS plugin/theme vulnerability DB (fingerprinting itself is done)

### Reporting & integration
- [ ] Email report delivery

### Scale & orchestration
- [ ] Distributed scanning (queue/worker model)

---
*Updated as batches land. Each `[x]` item has corresponding code in the repo —
this file is a tracker, not an aspirational spec.*
