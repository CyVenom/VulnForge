import asyncio

from aiohttp import web

from core.confidence import looks_distro_packaged, meets, parse_vuln_script
from core.cve_matcher import CVEMatcher
from core.web_scanner import WebScanner
from core.web_validators import (
    SENSITIVE_CHECKS, check_sensitive, find_stack_trace, fingerprint,
    is_catch_all, is_directory_listing,
)
from plugins.plugin_dns import DNSReconPlugin


# ---------------- validators ----------------
def test_word_error_is_not_a_stack_trace():
    assert find_stack_trace("<p>Sorry, an error occurred. Exception handling is hard.</p>") is None
    assert find_stack_trace("Traceback (most recent call last):\n  File x") is not None
    assert find_stack_trace("at com.acme.Foo.bar(Foo.java:42)") is not None
    assert find_stack_trace("Warning: Undefined variable in /var/www/a.php on line 12") is not None


def test_directory_listing_needs_real_markup():
    assert not is_directory_listing("<p>Here is an index of our products</p>")
    assert is_directory_listing("<html><head><title>Index of /images</title></head>")


def test_public_files_are_never_sensitive():
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/crossdomain.xml"):
        assert path not in SENSITIVE_CHECKS


def test_content_validators():
    html = b"<!doctype html><html><body>app</body></html>"
    assert check_sensitive("/.env", 200, html) is None
    assert check_sensitive("/.env", 200, b"DB_HOST=x\nSECRET_KEY=abc\n")[0] == "high"
    assert check_sensitive("/.env", 404, b"DB_HOST=x\nSECRET_KEY=abc\n") is None
    assert check_sensitive("/.git/HEAD", 200, b"ref: refs/heads/main\n") is not None
    assert check_sensitive("/.git/HEAD", 200, html) is None
    assert check_sensitive("/config.php", 200, b"") is None           # executed PHP: blank page
    assert check_sensitive("/config.php", 200, b"<?php define('DB_NAME','x');") is not None
    assert check_sensitive("/backup.zip", 200, b"PK\x03\x04rest") is not None
    assert check_sensitive("/backup.zip", 200, html) is None
    assert check_sensitive("/admin", 200, b"<h1>Welcome</h1>") is None
    assert check_sensitive("/admin", 200, b'<input type="password">')[0] == "low"


def test_catch_all_detection():
    page = b"<html>spa shell</html>"
    base = (200, *fingerprint(page))
    assert is_catch_all(base, 200, page)
    assert is_catch_all(base, 200, page + b"x" * 10)                  # near-identical length
    assert not is_catch_all(base, 200, b"x" * 5000)
    assert not is_catch_all((404, 0, ""), 200, page)
    assert not is_catch_all(None, 200, page)


# ---------------- confidence ----------------
def test_nmap_script_parsing():
    assert parse_vuln_script("x", "State: NOT VULNERABLE\n CVE-2014-0160") is None
    assert parse_vuln_script("x", "ERROR: Script execution failed CVE-2020-1") is None
    assert parse_vuln_script("x", "CVE-2020-1 mentioned but no verdict") is None
    assert parse_vuln_script("x", "State: LIKELY VULNERABLE")["confidence"] == "medium"
    v = parse_vuln_script("x", "State: VULNERABLE\n Risk factor: Critical  CVSSv2: 10.0")
    assert v == {"severity": "critical", "confidence": "confirmed"}
    assert parse_vuln_script("vulners", "cpe:/a:x\n CVE-2020-1 7.5")["confidence"] == "low"


def test_levels():
    assert meets("confirmed", "high") and meets("medium", "medium")
    assert not meets("low", "medium")
    assert meets(None, "high")                                         # unlabeled = deterministic


def test_distro_detection_and_matcher_downgrade(config):
    assert looks_distro_packaged("7.4p1 Debian 10+deb9u7")
    assert looks_distro_packaged(None, "Ubuntu Linux; protocol 2.0")
    assert not looks_distro_packaged("2.3.4", "")
    ports = {"22": {"state": "open", "port": 22, "proto": "tcp", "product": "OpenSSH", "service": "ssh",
                    "version": "7.4", "extrainfo": "Ubuntu Linux; protocol 2.0"}}
    hit = next(f for f in CVEMatcher(config).match_services({"ports": ports}) if f["cve"] == "CVE-2018-15473")
    assert hit["confidence"] == "medium" and "backports" in hit["title"]
    ports["22"]["extrainfo"] = "protocol 2.0"
    hit = next(f for f in CVEMatcher(config).match_services({"ports": ports}) if f["cve"] == "CVE-2018-15473")
    assert hit["confidence"] == "high"


# ---------------- DNS ----------------
def test_dmarc_parent_walk():
    assert DNSReconPlugin._dmarc_candidates("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert DNSReconPlugin._dmarc_candidates("example.com") == ["example.com"]


# ---------------- end to end against mock sites ----------------
SPA = "<!doctype html><html><head><title>App</title></head><body>Error handling docs. Exception safe.</body></html>"


async def scan_site(app, cfg_extra=None):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        res = await WebScanner({"web": {"timeout": 5}}).scan(f"http://127.0.0.1:{port}")
    finally:
        await runner.cleanup()
    return [f["title"] for f in res["findings"]]


def test_catch_all_spa_produces_no_sensitive_or_trace_findings():
    async def everything(r):
        return web.Response(text=SPA, content_type="text/html")

    app = web.Application()
    app.router.add_get("/{tail:.*}", everything)
    titles = asyncio.run(scan_site(app))
    assert not [t for t in titles if "Sensitive Path" in t]
    assert not [t for t in titles if "Stack Trace" in t]
    assert not [t for t in titles if "Directory Listing" in t]
    assert not [t for t in titles if "Strict-Transport" in t]          # plain HTTP: not applicable
    assert "HTTPS Not Available (Plain HTTP Only)" in titles


def test_real_env_file_is_still_found_and_frame_ancestors_respected():
    async def home(r):
        return web.Response(text="<html>ok</html>", content_type="text/html",
                            headers={"Content-Security-Policy": "frame-ancestors 'none'"})

    async def env(r):
        return web.Response(text="DB_HOST=db\nSECRET_KEY=abc123\n", content_type="text/plain")

    app = web.Application()
    app.router.add_get("/", home)
    app.router.add_get("/.env", env)
    titles = asyncio.run(scan_site(app))
    assert "Sensitive Path Exposed: /.env" in titles
    assert "Missing Security Header: X-Frame-Options" not in titles
    assert "Missing Security Header: Content-Security-Policy" not in titles
