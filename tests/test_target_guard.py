import pytest

from core.scanner import VulnForgeScanner
from core.target_guard import blocked_reason, extract_host

BLOCKED = ["169.254.0.0/16", "127.0.0.0/8", "::1/128", "198.51.100.0/24"]


def fake(mapping):
    return lambda host: mapping.get(host, [])


@pytest.mark.parametrize("target,host", [
    ("example.com", "example.com"),
    ("Example.COM", "example.com"),
    ("example.com:8443", "example.com"),
    ("https://example.com/a/b?q=1", "example.com"),
    ("http://user:pw@example.com:8080/x", "example.com"),
    ("203.0.113.9", "203.0.113.9"),
    ("203.0.113.9:80", "203.0.113.9"),
    ("[::1]:8080", "::1"),
    ("2001:db8::1", "2001:db8::1"),
    ("https://[2001:db8::1]:443/", "2001:db8::1"),
    ("example.com.", "example.com"),
    ("", ""),
])
def test_extract_host(target, host):
    assert extract_host(target) == host


def test_literal_ip_in_range_is_blocked():
    assert "169.254.169.254" in blocked_reason("169.254.169.254", BLOCKED)


def test_literal_ip_outside_range_is_allowed():
    assert blocked_reason("93.184.216.34", BLOCKED) is None


def test_hostname_resolving_into_blocked_range_is_blocked():
    # The old check let this through: it only inspected literal IPs.
    reason = blocked_reason("metadata.evil.test", BLOCKED, fake({"metadata.evil.test": ["169.254.169.254"]}))
    assert reason and "resolves to 169.254.169.254" in reason


def test_url_with_port_and_userinfo_is_checked_by_its_host():
    resolver = fake({"evil.test": ["198.51.100.7"]})
    assert blocked_reason("http://user@evil.test:8080/path?x=1", BLOCKED, resolver)


def test_any_blocked_address_among_several_blocks_the_target():
    resolver = fake({"multi.test": ["93.184.216.34", "127.0.0.1"]})
    assert blocked_reason("multi.test", BLOCKED, resolver)


def test_hostname_resolving_only_to_public_addresses_is_allowed():
    assert blocked_reason("fine.test", BLOCKED, fake({"fine.test": ["93.184.216.34"]})) is None


def test_ipv6_literal_and_bracketed_forms():
    assert blocked_reason("::1", BLOCKED)
    assert blocked_reason("[::1]:8080", BLOCKED)
    assert blocked_reason("http://[::1]/", BLOCKED)


def test_ipv4_mapped_ipv6_is_treated_as_the_ipv4_address():
    assert blocked_reason("::ffff:169.254.169.254", BLOCKED)


def test_odd_ip_spellings_are_caught_through_resolution():
    # "2130706433" and "0x7f.1" are 127.0.0.1 to the OS resolver.
    resolver = fake({"2130706433": ["127.0.0.1"], "0x7f.1": ["127.0.0.1"]})
    assert blocked_reason("2130706433", BLOCKED, resolver)
    assert blocked_reason("http://0x7f.1/", BLOCKED, resolver)


def test_unresolvable_name_is_not_blocked():
    assert blocked_reason("does-not-exist.invalid", BLOCKED, fake({})) is None


def test_no_ranges_or_empty_target_blocks_nothing():
    assert blocked_reason("127.0.0.1", []) is None
    assert blocked_reason("", BLOCKED) is None


def test_invalid_range_in_config_raises_instead_of_silently_allowing():
    with pytest.raises(ValueError, match="blocked_ranges"):
        blocked_reason("example.com", ["not-a-range"], fake({}))


def test_real_resolver_blocks_localhost():
    assert blocked_reason("localhost", BLOCKED)


def make_scanner(ranges):
    s = object.__new__(VulnForgeScanner)  # skip heavy __init__ (logging, databases)
    s.config = {"authorization": {"blocked_ranges": ranges}}
    return s


def test_scanner_blocks_hostname_that_resolves_to_a_blocked_range():
    s = make_scanner(BLOCKED)
    assert s._is_blocked("localhost") is True
    assert s._is_blocked("93.184.216.34") is False
    assert "127.0.0.1" in s._blocked_reason("http://127.0.0.1:8080/")
