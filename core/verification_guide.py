"""
VulnForge Verification Guide
Maps a finding's category to concrete manual verification steps, so every
automated finding comes with a way to confirm (or rule out) a false positive
by hand — via curl/openssl, browser devtools, or Burp Suite where Burp is
actually the right tool (it sits at the HTTP layer; it isn't useful for raw
TLS handshake or DNS checks, so those get openssl/dig instead).

This is intentionally a static, data-driven lookup — no network calls, no
AI judgment calls on exploitability. It tells you how to go verify a finding
yourself; it never claims a finding is confirmed on its own.
"""

GENERIC_STEPS = [
    "Re-run just this check in isolation to confirm it reproduces:\n"
    "       python vulnforge.py <target> -s <module> -o txt",
    "Open the full JSON report for this scan and locate this finding's 'evidence' "
    "field — compare it against the raw response you see manually.",
]

# category -> {"tools": [...], "steps": [...]}
GUIDES: dict[str, dict] = {
    "security_headers": {
        "tools": ["curl", "Burp Suite (Repeater)"],
        "steps": [
            "curl -sI https://<target>/   — look for the missing header in the response.",
            "Burp: send the request to Repeater, fire it, and check the Response "
            "'Headers' tab for the header named in the finding.",
            "If present but weak (e.g. a short HSTS max-age), check the exact value "
            "against OWASP's Secure Headers cheat sheet.",
        ],
    },
    "info_disclosure": {
        "tools": ["curl", "Burp Suite (Repeater)"],
        "steps": [
            "curl -sI https://<target>/   — confirm the disclosed header/value is still present.",
            "Burp: Repeater → send the request → check Response headers and body for "
            "the exact string quoted in 'evidence' (server banner, stack trace, etc.).",
            "If it's a stack trace, try to trigger the same error path manually "
            "(e.g. malformed input) to confirm it's reproducible, not a one-off.",
        ],
    },
    "cookies": {
        "tools": ["Browser DevTools", "Burp Suite (Proxy)"],
        "steps": [
            "Browser DevTools → Application/Storage → Cookies: check the Secure, "
            "HttpOnly, and SameSite columns for the named cookie.",
            "Burp: Proxy → HTTP history → open the response → 'Cookies' tab shows "
            "the same flags without needing the browser UI.",
            "curl -v https://<target>/ 2>&1 | grep -i set-cookie   — flags appear "
            "inline (e.g. 'HttpOnly; Secure; SameSite=Lax').",
        ],
    },
    "sensitive_files": {
        "tools": ["curl", "Burp Suite (Repeater)"],
        "steps": [
            "curl -i https://<target><path>   — confirm the HTTP status and that the "
            "body actually contains the sensitive content (a 200 with a generic SPA "
            "fallback page is a false positive).",
            "Burp: Repeater → GET the exact path from 'evidence' → inspect the "
            "response body, not just the status code.",
            "If it's a .git/HEAD hit, try: curl https://<target>/.git/config to see "
            "if the whole repo is actually exposed (confirms severity).",
        ],
    },
    "cors": {
        "tools": ["curl", "Burp Suite (Repeater)"],
        "steps": [
            "curl -i -H 'Origin: https://evil.example.com' https://<target>/<path>   "
            "— check the Access-Control-Allow-Origin / -Allow-Credentials response headers.",
            "Burp: Repeater → add/edit the Origin header manually → resend → confirm "
            "the server reflects your arbitrary origin back.",
            "To confirm real impact: if ACAO reflects your origin AND "
            "Allow-Credentials: true, host a tiny HTML page with a fetch() call using "
            "credentials:'include' pointed at a sensitive endpoint and see if it reads the response.",
        ],
    },
    "open_redirect": {
        "tools": ["curl", "Burp Suite (Repeater)"],
        "steps": [
            "curl -i 'https://<target>/<path>?redirect=https://evil.example.com'   "
            "— check the Location header in the 3xx response.",
            "Burp: Repeater → try each redirect-ish parameter name (redirect, url, "
            "next, return, continue) → check Location header on each response.",
            "Confirm it's a *real* redirect (whole-domain change) and not just a "
            "path-relative redirect that happens to contain your string.",
        ],
    },
    "directory_listing": {
        "tools": ["Browser", "curl"],
        "steps": [
            "Open https://<target><path> directly in a browser — look for an actual "
            "'Index of /...' style file listing, not a 403/404 page.",
            "curl -s https://<target><path> | grep -i 'index of'   — same check from the CLI.",
            "If listed, click into a file to confirm it's not an intentionally public asset.",
        ],
    },
    "jwt": {
        "tools": ["jwt.io (offline mode)", "Burp Suite JWT Editor extension"],
        "steps": [
            "Copy the token and decode it at jwt.io (use it OFFLINE / disconnect network "
            "first if the token could be sensitive) — check header.alg and payload.exp.",
            "Burp: install the 'JWT Editor' extension (BApp Store) → it auto-detects "
            "tokens in requests and lets you edit header/payload and re-sign.",
            "For alg=none: in JWT Editor, set alg to 'none', strip the signature, and "
            "resend the request — if it's still accepted, the finding is confirmed.",
            "For weak-secret: JWT Editor → 'Sign' tab → try the HMAC key VulnForge "
            "flagged (shown in the finding's evidence) and resend a modified token.",
        ],
    },
    "csp": {
        "tools": ["curl", "Google CSP Evaluator"],
        "steps": [
            "curl -sI https://<target>/ | grep -i content-security-policy   — get the "
            "exact raw policy string.",
            "Paste it into https://csp-evaluator.withgoogle.com/ for a directive-by-directive breakdown.",
            "Browser DevTools → Console: load the page and watch for CSP violation "
            "warnings, which confirm the policy is actually being enforced (or not).",
        ],
    },
    "ssl_protocol": {
        "tools": ["openssl", "testssl.sh"],
        "steps": [
            "openssl s_client -connect <target>:443 -tls1   (swap -tls1/-tls1_1/-ssl3 "
            "for the specific weak protocol named) — a successful handshake confirms it's accepted.",
            "testssl.sh <target>   — gives a full protocol/cipher matrix in one pass.",
            "Note: Burp Suite operates above the TLS layer (it's a proxy, not a TLS "
            "fuzzer) so it won't help verify this one directly.",
        ],
    },
    "ssl_cipher": {
        "tools": ["openssl", "testssl.sh"],
        "steps": [
            "openssl s_client -connect <target>:443 -cipher '<flagged cipher>'   — "
            "a successful connection confirms the server still offers it.",
            "testssl.sh --cipher-per-proto <target>   — enumerates every cipher per TLS version.",
        ],
    },
    "ssl_certificate": {
        "tools": ["openssl"],
        "steps": [
            "openssl s_client -connect <target>:443 -servername <target> </dev/null 2>/dev/null "
            "| openssl x509 -noout -dates -subject -issuer   — cross-check expiry/subject/issuer "
            "against the finding.",
            "For signature algorithm: add '-text' to the x509 command above and look "
            "for 'Signature Algorithm:'.",
        ],
    },
    "cve_match": {
        "tools": ["Manual banner grab", "searchsploit / Exploit-DB", "Vendor advisory"],
        "steps": [
            "Confirm the exact version first — banner grab manually: "
            "nc <target> <port>   or   curl -sI https://<target>:<port>/ depending on the service.",
            "searchsploit <product> <version>   — see if a known PoC exists for the matched CVE. "
            "If the finding names a Metasploit module, 'msfconsole -q -x \"info <module>\"' "
            "shows its target versions without running it.",
            "Check the vendor's own advisory for the CVE ID to confirm the affected version "
            "range matches exactly (VulnForge's local CVE dataset is a seed set, not authoritative).",
            "Only attempt the actual exploit PoC if you have explicit authorization to do so "
            "on this specific target.",
        ],
    },
    "transport": {
        "tools": ["curl", "Browser"],
        "steps": [
            "curl -sI https://<target>/   - if it fails to connect or errors, HTTPS is not available.",
            "Open https://<target>/ in a browser and see whether it loads without a certificate warning.",
            "curl -sI http://<target>/ | grep -i location   - check whether HTTP redirects to HTTPS.",
        ],
    },
    "graphql": {
        "tools": ["curl", "Burp Suite (Repeater)", "InQL (Burp extension)"],
        "steps": [
            "curl -s -X POST https://<target><path> -H 'Content-Type: application/json' "
            "-d '{\"query\":\"{__schema{queryType{name}}}\"}'   - a JSON body with "
            "data.__schema confirms introspection is on.",
            "Burp: Repeater -> POST the same body; the InQL extension can pull the full "
            "schema and generate queries from it.",
            "Judge impact by what the schema exposes (admin mutations, PII types), not "
            "just that introspection is enabled.",
        ],
    },
    "cms": {
        "tools": ["curl", "WPScan / CMSeeK", "Browser (view-source)"],
        "steps": [
            "View the page source and search for the generator meta tag and /wp-content/, "
            "/sites/default/ or /media/system/ paths to confirm the CMS.",
            "curl -s https://<target>/wp-json/wp/v2/users   - a JSON list of users "
            "confirms the WordPress enumeration finding.",
            "Cross-check the detected version against the vendor's release page; "
            "versions can be spoofed or hidden, so treat a missing version as unknown.",
        ],
    },
    "dns": {
        "tools": ["dig", "nslookup", "online DNS tools"],
        "steps": [
            "dig TXT <domain>   /   dig TXT _dmarc.<domain>   — re-check SPF/DMARC directly.",
            "dig AXFR <domain> @<nameserver>   — re-attempt the zone transfer manually "
            "(only if you have authorization) to confirm it still succeeds.",
            "For discovered subdomains: dig A <subdomain>   to confirm they still resolve "
            "and aren't stale DNS records.",
            "To re-check the CT-log list yourself: open https://crt.sh/?q=%25.<domain> "
            "in a browser and compare against the finding's evidence.",
        ],
    },
    "http_methods": {
        "tools": ["curl", "Burp Suite (Repeater)"],
        "steps": [
            "curl -i -X TRACE https://<target>/   (swap TRACE for the flagged method) — "
            "check if the server actually processes it rather than returning 405/501.",
            "Burp: Repeater → change the HTTP method dropdown at the top of the request "
            "editor → resend → inspect the response.",
        ],
    },
    "xss": {
        "tools": ["Browser DevTools", "Burp Suite (Repeater)"],
        "steps": [
            "Re-send the exact URL in 'evidence' and view-source the response — confirm "
            "the marker appears unescaped (not as &lt;vfxss...&gt;).",
            "Burp: Repeater → replace the marker with a real payload like "
            "<script>alert(document.domain)</script> → render the response in Burp's "
            "built-in browser to confirm actual script execution, not just reflection.",
            "Check whether the reflection point is inside an HTML attribute, a <script> "
            "block, or plain body text — the right payload differs by context.",
        ],
    },
    "sqli": {
        "tools": ["curl", "Burp Suite (Repeater)", "sqlmap"],
        "steps": [
            "curl -i '<evidence URL>'   — resend the single-quote or boolean payload and "
            "confirm the error text / response-length delta reproduces.",
            "Burp: Repeater → toggle between the '1'='1 and '1'='2' payloads → diff the "
            "two responses directly in Burp's comparer.",
            "sqlmap -u '<url>?<param>=1' -p <param>   — only against a target you're "
            "authorized to actively exploit; confirms the injection and its type (error/boolean/time-based).",
        ],
    },
    "ssrf": {
        "tools": ["curl", "Burp Suite (Repeater)", "Collaborator / canary domain"],
        "steps": [
            "curl -i '<evidence URL>'   — resend and confirm the metadata/loopback "
            "signature still appears in the response body.",
            "Burp: Repeater → try other internal targets (http://localhost:<port>, "
            "cloud-provider metadata IPs for AWS/GCP/Azure) via the same parameter.",
            "For blind SSRF (no reflection): point the parameter at a Burp Collaborator "
            "or similar canary URL and watch for an out-of-band DNS/HTTP callback.",
        ],
    },
    "command_injection": {
        "tools": ["curl", "Burp Suite (Repeater)"],
        "steps": [
            "curl -i '<evidence URL>'   — resend and confirm the echoed token still "
            "appears in the response body.",
            "Burp: Repeater → try the other shell metacharacters (;, |, `` ` ``, "
            "$()) individually to map exactly which one the server doesn't sanitize.",
            "Confirm impact scope by trying a harmless read-only command (e.g. "
            "'id' or 'whoami' equivalent) — never a destructive command.",
        ],
    },
    "dir_bruteforce": {
        "tools": ["curl", "Browser"],
        "steps": [
            "curl -i https://<target><path>   — confirm the status/content-type still "
            "matches what was recorded (brute-force hits can be stale).",
            "Open the path in a browser to rule out a soft-404 / catch-all page that "
            "slipped past the baseline comparison.",
        ],
    },
    "cloud_storage": {
        "tools": ["curl", "AWS CLI / gsutil / az storage"],
        "steps": [
            "curl -i '<evidence URL>'   — confirm the bucket still returns a public "
            "listing (ListBucketResult / JSON array / EnumerationResults), not AccessDenied.",
            "aws s3 ls s3://<bucket> --no-sign-request   (swap for gsutil ls / az "
            "storage blob list for GCS/Azure) — confirms anonymous listing from the "
            "provider's own CLI, independent of the raw HTTP check.",
            "Do not attempt to write/delete objects without explicit authorization — "
            "this check only confirms read exposure.",
        ],
    },
    "default_credentials": {
        "tools": ["curl", "Browser", "ftp client"],
        "steps": [
            "Re-attempt the exact credential pair named in 'evidence' manually against "
            "the same service to rule out a transient fluke.",
            "Check whether the account that logged in has any real privileges — a "
            "default account with no access is a much lower-severity finding.",
            "Only tested with your own explicit extra authorization for credential "
            "testing — treat any successful login as sensitive and rotate it immediately.",
        ],
    },
    "host_discovery": {
        "tools": ["ping", "nmap"],
        "steps": [
            "ping -n 1 <host>  (or -c 1 on Linux/Mac) / nmap -sn <host>   — confirm the "
            "host-alive result independently; ICMP can be blocked while TCP ports answer, or vice versa.",
        ],
    },
    "port_scan": {
        "tools": ["nmap", "nc (netcat)", "searchsploit"],
        "steps": [
            "nmap -sV -p <port> <target>   — re-confirm the service/version independently.",
            "nc <target> <port>   — manually grab the banner for services that print one on connect.",
            "searchsploit <service> <version>   — check for known public exploits matching "
            "the exact banner before assuming the nmap vuln-script output is accurate.",
        ],
    },
}


def get_verification_steps(finding: dict) -> dict:
    """
    Return {"tools": [...], "steps": [...]} for a finding, keyed by its
    'category' field (falling back to its 'source' field, then a generic
    guide if neither is recognized).
    """
    category = (finding.get("category") or "").lower()
    source = (finding.get("source") or "").lower()

    guide = GUIDES.get(category)
    if guide is None:
        # source values look like "plugin:dns_recon" / "web_scan" / "cve_matcher"
        for key in GUIDES:
            if key in source:
                guide = GUIDES[key]
                break

    if guide is None:
        return {"tools": ["Manual re-check"], "steps": list(GENERIC_STEPS)}

    return {"tools": guide["tools"], "steps": guide["steps"] + GENERIC_STEPS[:1]}
