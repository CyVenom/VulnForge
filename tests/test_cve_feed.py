import asyncio
import json

from aiohttp import web

from core.cve_matcher import CVEMatcher, _parse_version, in_range
from core.cve_sync import build_entries, cvss_of, extract_ranges, severity_from_cvss, sync


def cpe(vendor, product, version="*"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def nvd_item(cve_id, matches, score=9.8, status="Analyzed"):
    return {"cve": {
        "id": cve_id, "vulnStatus": status, "published": "2024-01-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Something   bad\nhappens."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": matches}]}],
    }}


def m(vendor, product, version="*", vulnerable=True, **bounds):
    return {"vulnerable": vulnerable, "criteria": cpe(vendor, product, version), **bounds}


# ---------------- version logic ----------------
def test_letter_suffix_versions_order():
    assert _parse_version("1.0.1f") < _parse_version("1.0.1g")
    assert _parse_version("7.4p1") == (7, 4)
    assert _parse_version("8.2p1 Ubuntu") == (8, 2)


def test_in_range_bounds():
    r = {"si": "2.4.49", "ee": "2.4.51"}
    assert in_range((2, 4, 49), r) and in_range((2, 4, 50), r)
    assert not in_range((2, 4, 51), r) and not in_range((2, 4, 48), r)
    assert in_range((7, 7), {"ei": "7.7"}) and not in_range((7, 8), {"ei": "7.7"})
    assert not in_range((1, 0), {"se": "1.0"})
    assert not in_range((1, 0), {"ei": "garbage"})        # unparseable bound: never guess


# ---------------- extraction ----------------
def test_extract_ranges_variants():
    cve = nvd_item("CVE-1", [
        m("openbsd", "openssh", versionEndIncluding="7.7"),
        m("openbsd", "openssh", "7.4"),                     # exact version
        m("openbsd", "openssh"),                            # "all versions": unusable
        m("openbsd", "openssh", vulnerable=False, versionEndIncluding="9.9"),
        m("debian", "debian_linux", "9.0"),                 # OS CPE ignored
        m("other", "openssh", versionEndIncluding="1.0"),   # wrong vendor
    ])["cve"]
    assert extract_ranges(cve, "openbsd", "openssh") == [{"ei": "7.7"}, {"si": "7.4", "ei": "7.4"}]


def test_build_entries_filters():
    items = [
        nvd_item("CVE-HI", [m("v", "p", versionEndExcluding="2.0")], 9.8),
        nvd_item("CVE-LOW", [m("v", "p", versionEndExcluding="2.0")], 4.0),
        nvd_item("CVE-KEV-LOW", [m("v", "p", versionEndExcluding="2.0")], 4.0),
        nvd_item("CVE-REJ", [m("v", "p", versionEndExcluding="2.0")], 9.8, status="Rejected"),
        nvd_item("CVE-NORANGE", [m("v", "p")], 9.8),
    ]
    got = build_entries(items, "v", "p", {"CVE-KEV-LOW"}, 7.0)
    assert [e["cve"] for e in got] == ["CVE-HI", "CVE-KEV-LOW"]
    assert got[0]["severity"] == "critical" and got[1]["kev"] is True
    assert "\n" not in got[0]["description"] and "  " not in got[0]["description"]
    assert cvss_of({}) == 0.0 and severity_from_cvss(7.5) == "high"


# ---------------- sync against a mock NVD/KEV ----------------
def test_sync_end_to_end_with_pagination(tmp_path):
    pages = {0: [nvd_item("CVE-A", [m("v", "p", versionEndExcluding="2.0")])],
             1: [nvd_item("CVE-B", [m("v", "p", versionEndExcluding="3.0")])]}

    async def nvd(r):
        start = int(r.query["startIndex"])
        return web.json_response({"totalResults": 2, "vulnerabilities": pages.get(start, [])})

    async def kev(r):
        return web.json_response({"vulnerabilities": [{"cveID": "CVE-B"}]})

    async def main():
        app = web.Application()
        app.router.add_get("/nvd", nvd)
        app.router.add_get("/kev", kev)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        out = tmp_path / "feed.json"
        try:
            import core.cve_sync as cs
            cs.DELAY_WITH_KEY = 0.01
            report = await sync(["v:p"], str(out), api_key="k", nvd_url=f"http://127.0.0.1:{port}/nvd",
                                kev_url=f"http://127.0.0.1:{port}/kev")
        finally:
            await runner.cleanup()
        return report, json.loads(out.read_text(encoding="utf-8"))

    report, doc = asyncio.run(main())
    assert report["products"] == {"v:p": 2} and report["kev_total"] == 1
    assert {e["cve"]: e["kev"] for e in doc["entries"]} == {"CVE-A": False, "CVE-B": True}


# ---------------- matcher using the feed ----------------
def feed_matcher(config, tmp_path, entries):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    config = {**config, "cve_matcher": {**config["cve_matcher"], "feed_path": str(feed)}}
    return CVEMatcher(config)


def port(product, version, cpes, extrainfo="", n=80):
    return {"state": "open", "port": n, "proto": "tcp", "product": product, "service": "http",
            "version": version, "extrainfo": extrainfo, "cpe": cpes}


ENTRY = {"cve": "CVE-F-1", "vendor": "f5", "product": "nginx", "kev": False, "cvss": 7.7, "severity": "high",
         "ranges": [{"si": "0.6.18", "ee": "1.20.1"}], "description": "nginx resolver bug"}


def run(matcher, p):
    return [f for f in matcher.match_services({"ports": {"80": p}}) if f["cve"] == "CVE-F-1"]


def test_feed_match_via_cpe_with_vendor_alias(config, tmp_path):
    mt = feed_matcher(config, tmp_path, [ENTRY])
    hit = run(mt, port("nginx", "1.18.0", ["cpe:/a:igor_sysoev:nginx:1.18.0"]))
    assert len(hit) == 1 and hit[0]["confidence"] == "high"          # igor_sysoev -> f5 alias not needed: product distinctive
    assert run(mt, port("nginx", "1.20.1", ["cpe:/a:igor_sysoev:nginx:1.20.1"])) == []   # fixed version
    assert run(mt, port("nginx", "0.5.0", ["cpe:/a:igor_sysoev:nginx:0.5.0"])) == []     # before range


def test_feed_never_guesses_without_version(config, tmp_path):
    mt = feed_matcher(config, tmp_path, [ENTRY])
    assert run(mt, port("nginx", "", [])) == []


def test_feed_distro_builds_downgraded_unless_kev(config, tmp_path):
    mt = feed_matcher(config, tmp_path, [ENTRY, {**ENTRY, "cve": "CVE-KEV", "kev": True}])
    out = mt.match_services({"ports": {"80": port("nginx", "1.4.6", ["cpe:/a:igor_sysoev:nginx:1.4.6"], "Ubuntu")}})
    conf = {f["cve"]: f["confidence"] for f in out}
    assert conf["CVE-F-1"] == "low" and conf["CVE-KEV"] == "medium"
    assert "CISA KEV" in next(f for f in out if f["cve"] == "CVE-KEV")["title"]


def test_generic_product_requires_matching_vendor(config, tmp_path):
    entry = {"cve": "CVE-G", "vendor": "apache", "product": "http_server", "kev": False, "severity": "high",
             "ranges": [{"ee": "2.4.50"}], "description": "x"}
    mt = feed_matcher(config, tmp_path, [entry])
    ok = mt.match_services({"ports": {"80": port("Apache httpd", "2.4.49", ["cpe:/a:apache:http_server:2.4.49"])}})
    bad = mt.match_services({"ports": {"80": port("IBM HTTP Server", "2.4.49", ["cpe:/a:ibm:http_server:2.4.49"])}})
    assert [f["cve"] for f in ok if f["cve"] == "CVE-G"] and not [f for f in bad if f["cve"] == "CVE-G"]


def test_curated_entry_wins_over_feed_duplicate(config, tmp_path):
    entry = {"cve": "CVE-2011-2523", "vendor": "vsftpd_project", "product": "vsftpd", "kev": False,
             "severity": "high", "ranges": [{"si": "2.3.4", "ei": "2.3.4"}], "description": "dup"}
    mt = feed_matcher(config, tmp_path, [entry])
    p = {"state": "open", "port": 21, "proto": "tcp", "product": "vsftpd", "service": "ftp", "version": "2.3.4",
         "cpe": ["cpe:/a:vsftpd_project:vsftpd:2.3.4"]}
    hits = [f for f in mt.match_services({"ports": {"21": p}}) if f["cve"] == "CVE-2011-2523"]
    assert len(hits) == 1 and hits[0]["public_poc"]                  # the curated one, with its PoC reference
