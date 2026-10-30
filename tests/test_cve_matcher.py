from core.cve_matcher import CVEMatcher, _parse_version, _version_cmp


def port(product, version, n=21):
    return {"state": "open", "port": n, "proto": "tcp", "product": product, "service": "x", "version": version}


def test_parse_version():
    assert _parse_version("7.4p1") == (7, 4)
    assert _parse_version("") is None
    assert _parse_version("abc") is None


def test_version_cmp_pads_zeros():
    assert _version_cmp((2, 4), (2, 4, 0)) == 0
    assert _version_cmp((2, 4, 49), (2, 4, 50)) == -1


def test_affected_version_matches_with_poc(config):
    out = CVEMatcher(config).match_services({"ports": {"21": port("vsftpd", "2.3.4")}})
    hit = next(f for f in out if f["cve"] == "CVE-2011-2523")
    assert hit["confidence"] == "high"
    assert hit["public_poc"]["metasploit"]
    assert "public exploit" in hit["description"]


def test_patched_version_not_flagged(config):
    out = CVEMatcher(config).match_services({"ports": {"21": port("vsftpd", "3.0.5")}})
    assert not [f for f in out if f["cve"] == "CVE-2011-2523"]


def test_missing_version_is_low_confidence(config):
    out = CVEMatcher(config).match_services({"ports": {"21": port("vsftpd", "")}})
    hits = [f for f in out if f["cve"] == "CVE-2011-2523"]
    assert hits and all(f["confidence"] == "low" for f in hits)


def test_closed_ports_ignored(config):
    p = port("vsftpd", "2.3.4")
    p["state"] = "closed"
    assert CVEMatcher(config).match_services({"ports": {"21": p}}) == []


def test_entry_without_poc_has_none(config):
    out = CVEMatcher(config).match_services({"ports": {"22": port("OpenSSH", "7.4", 22)}})
    hit = next(f for f in out if f["cve"] == "CVE-2018-15473")
    assert hit["public_poc"] is None
