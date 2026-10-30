"""
VulnForge Web Validators
Content checks that turn "the server answered 200" into "the response really
is the sensitive thing". A 200 on /.env or /config.php is meaningless on its
own: single-page apps and catch-all routers answer 200 for everything, and
PHP files normally execute rather than leak. Each check here looks at the
body and says whether it matches what a genuine exposure would contain.
Pure functions, no network.
"""
import hashlib
import re

# ---- error / stack trace signatures (specific, not the word "error") ----
STACK_TRACE_PATTERNS = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)"),
    re.compile(r'Exception in thread "'),
    re.compile(r"(?:Fatal error|Warning|Parse error|Notice): .{0,200}? in [/\\\w.\-: ]+\.php on line \d+"),
    re.compile(r"Server Error in '[^']*' Application"),
    re.compile(r"\bat [\w.]+\.[\w.<>$]+ in [^\n]+:line \d+"),
    re.compile(r"System\.\w+Exception:"),
    re.compile(r"\(node_modules/[^)\n]+\.js:\d+:\d+\)"),
    re.compile(r"You have an error in your SQL syntax"),
    re.compile(r"\bORA-\d{5}:"),
    re.compile(r"\bat \w+ \([^)\n]*\.js:\d+:\d+\)"),
]


def find_stack_trace(body: str) -> str | None:
    """Return the first matching signature text, or None."""
    for pattern in STACK_TRACE_PATTERNS:
        m = pattern.search(body)
        if m:
            return m.group(0)[:120]
    return None


# ---- directory listing ----
LISTING_PATTERNS = [
    re.compile(r"<title>\s*Index of /", re.I),
    re.compile(r"<h1>\s*Index of /", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),
    re.compile(r"<title>[^<]*- /[^<]*</title>.*Directory Listing", re.I | re.S),
]


def is_directory_listing(body: str) -> bool:
    return any(p.search(body) for p in LISTING_PATTERNS)


# ---- soft-404 / catch-all detection ----
def fingerprint(body: bytes) -> tuple[int, str]:
    return len(body), hashlib.sha256(body).hexdigest()


def is_catch_all(baseline: tuple[int, int, str] | None, status: int, body: bytes) -> bool:
    """
    baseline = (status, length, sha256) of a request to a path that cannot
    exist. If the site answers 200 for that too, it is a catch-all router
    and a 200 on a probed path proves nothing, unless the body differs.
    """
    if baseline is None or baseline[0] != 200 or status != 200:
        return False
    length, digest = fingerprint(body)
    if digest == baseline[2]:
        return True
    return abs(length - baseline[1]) <= max(64, int(baseline[1] * 0.02))


def _looks_html(body: bytes) -> bool:
    head = body[:512].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html")) or b"<head" in head or b"<body" in head


def _text(body: bytes) -> str:
    return body[:65536].decode("utf-8", "replace")


ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=\s*\S", re.M)


def _v_git_head(b: bytes) -> bool:
    t = _text(b).strip()
    return t.startswith("ref: refs/") or bool(re.fullmatch(r"[0-9a-f]{40}", t))


def _v_env(b: bytes) -> bool:
    return not _looks_html(b) and len(ENV_LINE.findall(_text(b))) >= 2


def _v_zip(b: bytes) -> bool:
    return b[:4] == b"PK\x03\x04"


def _v_php_source(b: bytes) -> bool:
    t = _text(b)
    return "<?php" in t and bool(re.search(r"DB_(NAME|USER|PASSWORD)|define\s*\(|\$\w+\s*=", t))


def _v_phpinfo(b: bytes) -> bool:
    t = _text(b)
    return "phpinfo()" in t or ("PHP Version" in t and "System" in t and "Configuration" in t)


def _v_htaccess(b: bytes) -> bool:
    return not _looks_html(b) and bool(re.search(r"(?im)^\s*(RewriteEngine|RewriteRule|AuthType|Require|Order|Options|Header|AddType)\b", _text(b)))


def _v_web_config(b: bytes) -> bool:
    return "<configuration" in _text(b).lower()


def _v_ds_store(b: bytes) -> bool:
    return b[:8] == b"\x00\x00\x00\x01Bud1"


def _v_openapi(b: bytes) -> bool:
    t = _text(b)
    return bool(re.search(r'"(swagger|openapi)"\s*:\s*"', t))


def _v_swagger_ui(b: bytes) -> bool:
    return "swagger-ui" in _text(b).lower()


def _v_actuator_env(b: bytes) -> bool:
    return '"propertySources"' in _text(b) or '"activeProfiles"' in _text(b)


def _v_actuator_index(b: bytes) -> bool:
    return '"_links"' in _text(b)


def _v_actuator_health(b: bytes) -> bool:
    return bool(re.search(r'"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"', _text(b)))


def _v_login_form(b: bytes) -> bool:
    return bool(re.search(r'type=["\']?password', _text(b), re.I))


# path -> (validator, severity, what a pass means). Intentionally public files
# (robots.txt, sitemap.xml, security.txt, crossdomain.xml) are NOT here.
SENSITIVE_CHECKS: dict[str, tuple] = {
    "/.git/HEAD": (_v_git_head, "high", "Git repository metadata is downloadable"),
    "/.env": (_v_env, "high", "Environment file with KEY=value pairs is downloadable"),
    "/.env.backup": (_v_env, "high", "Environment backup with KEY=value pairs is downloadable"),
    "/backup.zip": (_v_zip, "high", "A ZIP archive is downloadable"),
    "/wp-config.php": (_v_php_source, "critical", "PHP source with configuration is served as text"),
    "/config.php": (_v_php_source, "high", "PHP source with configuration is served as text"),
    "/phpinfo.php": (_v_phpinfo, "medium", "phpinfo() output is publicly reachable"),
    "/.htaccess": (_v_htaccess, "medium", "Apache configuration file is downloadable"),
    "/web.config": (_v_web_config, "high", "IIS configuration file is downloadable"),
    "/.DS_Store": (_v_ds_store, "low", "macOS directory metadata file is downloadable"),
    "/api/swagger.json": (_v_openapi, "low", "API specification is publicly readable"),
    "/api/openapi.json": (_v_openapi, "low", "API specification is publicly readable"),
    "/swagger-ui.html": (_v_swagger_ui, "low", "Swagger UI is publicly reachable"),
    "/actuator": (_v_actuator_index, "medium", "Spring Boot Actuator index is exposed"),
    "/actuator/env": (_v_actuator_env, "high", "Spring Boot environment properties are exposed"),
    "/actuator/health": (_v_actuator_health, "low", "Actuator health endpoint is exposed"),
    "/admin": (_v_login_form, "low", "An administrative login page is reachable from the internet"),
    "/admin/login": (_v_login_form, "low", "An administrative login page is reachable from the internet"),
}


def check_sensitive(path: str, status: int, body: bytes) -> tuple[str, str] | None:
    """Return (severity, reason) if the response genuinely matches, else None."""
    entry = SENSITIVE_CHECKS.get(path)
    if entry is None or status != 200:
        return None
    validator, severity, reason = entry
    return (severity, reason) if validator(body) else None
