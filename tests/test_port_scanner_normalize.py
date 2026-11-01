from core.port_scanner import PortScanner


def test_strips_scheme_and_path():
    assert PortScanner._normalize_host("https://pentagi.com/") == "pentagi.com"
    assert PortScanner._normalize_host("http://example.com/a/b?q=1") == "example.com"


def test_strips_path_without_scheme():
    assert PortScanner._normalize_host("klcc.org/npr-news/2026-10-28/x") == "klcc.org"
    assert PortScanner._normalize_host("malay.1xbet.com/en?v=1") == "malay.1xbet.com"


def test_bare_hostname_and_ip_untouched():
    assert PortScanner._normalize_host("scanme.nmap.org") == "scanme.nmap.org"
    assert PortScanner._normalize_host("192.168.1.1") == "192.168.1.1"


def test_strips_trailing_port():
    assert PortScanner._normalize_host("example.com:8443") == "example.com"


def test_bracketed_ipv6_kept_intact():
    assert PortScanner._normalize_host("[::1]:443") == "[::1]:443"
