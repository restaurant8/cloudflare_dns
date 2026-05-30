import pytest

from app.dns_utils import normalize_hostname, parse_target, record_type_for_target_type


def test_parse_target_detects_ipv4_ipv6_and_hostname():
    assert parse_target("192.0.2.10").target_type == "ipv4"
    assert parse_target("192.0.2.10").record_type == "A"
    assert parse_target("2001:db8::1").target_type == "ipv6"
    assert parse_target("2001:db8::1").record_type == "AAAA"
    info = parse_target("Backup.Example.COM.")
    assert info.target_type == "hostname"
    assert info.record_type == "CNAME"
    assert info.value == "backup.example.com"


def test_rejects_invalid_targets():
    for value in ["", "https://example.com", "bad host.example.com", "example"]:
        with pytest.raises(ValueError):
            parse_target(value)


def test_record_type_for_target_type():
    assert record_type_for_target_type("ipv4") == "A"
    assert record_type_for_target_type("ipv6") == "AAAA"
    assert record_type_for_target_type("hostname") == "CNAME"
    with pytest.raises(ValueError):
        record_type_for_target_type("txt")


def test_normalize_hostname_uses_idna():
    assert normalize_hostname("WWW.Example.COM.") == "www.example.com"

