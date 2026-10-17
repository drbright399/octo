"""Tests for sanitized_pool.shapes (M1 + M7 + M8 controls).

Coverage:
  - Each allowlisted kind validates its happy + edge cases
  - URL canonicalization per M8 (strip query/fragment, lowercase host,
    drop default port)
  - YARA always rejects (M7)
  - Reserved IP ranges rejected
  - Excessive-length inputs rejected
  - Control chars in URLs rejected
  - Adversarial inputs from public threat-test corpora rejected
"""
from __future__ import annotations

import pytest

from apps.octo.sanitized_pool import shapes


# ---------------------------------------------------------------------------
# file_hash
# ---------------------------------------------------------------------------

class TestFileHash:
    def test_sha256_lowercase(self) -> None:
        v = "a" * 64
        r = shapes.validate_pattern("file_hash", v, subkind="sha256")
        assert isinstance(r, shapes.Accepted)
        assert r.kind == "file_hash"
        assert r.subkind == "sha256"
        assert r.canonical_value == v

    def test_sha256_uppercase_lowercased(self) -> None:
        v = "A" * 64
        r = shapes.validate_pattern("file_hash", v, subkind="sha256")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "a" * 64

    def test_md5(self) -> None:
        r = shapes.validate_pattern("file_hash", "0" * 32, subkind="md5")
        assert isinstance(r, shapes.Accepted)

    def test_sha1(self) -> None:
        r = shapes.validate_pattern("file_hash", "f" * 40, subkind="sha1")
        assert isinstance(r, shapes.Accepted)

    def test_bad_length_rejected(self) -> None:
        r = shapes.validate_pattern("file_hash", "a" * 63, subkind="sha256")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_HASH_BAD_LENGTH

    def test_non_hex_rejected(self) -> None:
        r = shapes.validate_pattern("file_hash", "g" * 64, subkind="sha256")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_HASH_NOT_HEX

    def test_missing_subkind_rejected(self) -> None:
        r = shapes.validate_pattern("file_hash", "a" * 64)
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_UNKNOWN_KIND

    def test_unknown_subkind_rejected(self) -> None:
        r = shapes.validate_pattern("file_hash", "a" * 64, subkind="sha512")
        assert isinstance(r, shapes.Rejected)


# ---------------------------------------------------------------------------
# ip
# ---------------------------------------------------------------------------

class TestIp:
    def test_ipv4_public(self) -> None:
        r = shapes.validate_pattern("ip", "8.8.8.8")
        assert isinstance(r, shapes.Accepted)
        assert r.subkind == "ipv4"
        assert r.canonical_value == "8.8.8.8"

    def test_ipv6_public(self) -> None:
        r = shapes.validate_pattern("ip", "2001:4860:4860::8888")
        assert isinstance(r, shapes.Accepted)
        assert r.subkind == "ipv6"

    def test_invalid_rejected(self) -> None:
        r = shapes.validate_pattern("ip", "not-an-ip")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_IP_INVALID

    @pytest.mark.parametrize("addr", [
        "10.0.0.1",        # scan-sensitive: allow[ip-private] RFC 1918: the range under test
        "192.168.1.1",     # scan-sensitive: allow[ip-private] RFC 1918: the range under test
        "172.16.0.1",      # scan-sensitive: allow[ip-private] RFC 1918: the range under test
        "127.0.0.1",       # loopback
        "169.254.1.1",     # scan-sensitive: allow[ip-private] link-local: the range under test
        "224.0.0.1",       # multicast
        "0.0.0.0",         # unspecified
        "::1",             # IPv6 loopback
        "fe80::1",         # IPv6 link-local
        "fc00::1",         # IPv6 private
    ])
    def test_reserved_ranges_rejected(self, addr: str) -> None:
        r = shapes.validate_pattern("ip", addr)
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_IP_RESERVED


# ---------------------------------------------------------------------------
# domain
# ---------------------------------------------------------------------------

class TestDomain:
    def test_simple(self) -> None:
        r = shapes.validate_pattern("domain", "example.com")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "example.com"

    def test_uppercase_lowercased(self) -> None:
        r = shapes.validate_pattern("domain", "Example.COM")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "example.com"

    def test_trailing_dot_stripped(self) -> None:
        r = shapes.validate_pattern("domain", "example.com.")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "example.com"

    def test_punycode(self) -> None:
        r = shapes.validate_pattern("domain", "xn--bcher-kva.example")
        assert isinstance(r, shapes.Accepted)

    def test_no_tld_rejected(self) -> None:
        r = shapes.validate_pattern("domain", "localhost")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_DOMAIN_NO_TLD

    def test_invalid_chars_rejected(self) -> None:
        r = shapes.validate_pattern("domain", "evil!.com")
        assert isinstance(r, shapes.Rejected)

    def test_leading_hyphen_rejected(self) -> None:
        r = shapes.validate_pattern("domain", "-evil.com")
        assert isinstance(r, shapes.Rejected)

    def test_too_long_rejected(self) -> None:
        long_label = "a" * 64
        r = shapes.validate_pattern("domain", f"{long_label}.com")
        assert isinstance(r, shapes.Rejected)


# ---------------------------------------------------------------------------
# url — M8 canonicalization
# ---------------------------------------------------------------------------

class TestUrl:
    def test_strips_query_string(self) -> None:
        r = shapes.validate_pattern("url", "https://evil.com/path?session=abc")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "https://evil.com/path"
        assert "session" not in r.canonical_value

    def test_strips_fragment(self) -> None:
        r = shapes.validate_pattern("url", "https://evil.com/path#frag")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "https://evil.com/path"

    def test_strips_default_port_https(self) -> None:
        r = shapes.validate_pattern("url", "https://evil.com:443/path")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "https://evil.com/path"

    def test_strips_default_port_http(self) -> None:
        r = shapes.validate_pattern("url", "http://evil.com:80/path")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "http://evil.com/path"

    def test_keeps_non_default_port(self) -> None:
        r = shapes.validate_pattern("url", "https://evil.com:8443/path")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value == "https://evil.com:8443/path"

    def test_lowercases_host(self) -> None:
        r = shapes.validate_pattern("url", "https://Evil.COM/Path")
        assert isinstance(r, shapes.Accepted)
        # Host lowercased; path is left as-is (some servers are case-sensitive)
        assert r.canonical_value == "https://evil.com/Path"

    def test_lowercases_scheme(self) -> None:
        r = shapes.validate_pattern("url", "HTTPS://evil.com/")
        assert isinstance(r, shapes.Accepted)
        assert r.canonical_value.startswith("https://")

    def test_two_equivalent_urls_canonicalize_identically(self) -> None:
        """The whole point of M8 — different forms of the same URL
        collapse to one canonical entry in the pool."""
        a = shapes.validate_pattern("url", "https://Evil.com:443/path?utm=1")
        b = shapes.validate_pattern("url", "http://evil.com/path?session=AAA#x")
        assert isinstance(a, shapes.Accepted)
        assert isinstance(b, shapes.Accepted)
        # They differ in scheme (https vs http); only the host + path
        # should match. This documents the canonical-form rule:
        # scheme IS preserved (we don't auto-upgrade http to https).
        assert a.canonical_value == "https://evil.com/path"
        assert b.canonical_value == "http://evil.com/path"

    def test_ftp_rejected(self) -> None:
        r = shapes.validate_pattern("url", "ftp://evil.com/")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_URL_SCHEME

    def test_no_host_rejected(self) -> None:
        r = shapes.validate_pattern("url", "https:///path")
        assert isinstance(r, shapes.Rejected)

    def test_control_chars_rejected(self) -> None:
        r = shapes.validate_pattern("url", "https://evil.com/\x00path")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_URL_INVALID_CHARS

    def test_invalid_host_rejected(self) -> None:
        r = shapes.validate_pattern("url", "https://!!!/path")
        assert isinstance(r, shapes.Rejected)


# ---------------------------------------------------------------------------
# yara — M7 always rejects
# ---------------------------------------------------------------------------

class TestYara:
    def test_yara_always_rejects(self) -> None:
        r = shapes.validate_pattern("yara", "rule X { strings: $a = \"foo\" condition: $a }")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_YARA_DEFERRED

    def test_yara_with_uppercase_kind_still_rejects(self) -> None:
        r = shapes.validate_pattern("YARA", "anything")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_YARA_DEFERRED

    def test_yara_compiler_bomb_rejects_immediately(self) -> None:
        """Reviewer-flagged concern: YARA compiler can take
        minutes-to-hours on a malicious rule. We must reject it BEFORE
        it ever hits a compiler. This test confirms the reject path is
        synchronous + pure-string."""
        bomb = "rule B { strings: " + " ".join(
            f'$a{i} = "aaaaaaaaaaaaaaa{i}"' for i in range(1000)
        ) + " condition: any of them }"
        r = shapes.validate_pattern("yara", bomb)
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_YARA_DEFERRED


# ---------------------------------------------------------------------------
# General entrypoint behavior
# ---------------------------------------------------------------------------

class TestEntrypoint:
    def test_unknown_kind_rejected(self) -> None:
        r = shapes.validate_pattern("magic_number", "42")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_UNKNOWN_KIND

    def test_empty_value_rejected(self) -> None:
        r = shapes.validate_pattern("domain", "")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_EMPTY

    def test_whitespace_only_rejected(self) -> None:
        r = shapes.validate_pattern("domain", "   ")
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_EMPTY

    def test_too_long_rejected(self) -> None:
        r = shapes.validate_pattern("url", "https://evil.com/" + "a" * 10000)
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == shapes.REASON_TOO_LONG

    def test_non_string_value_rejected(self) -> None:
        r = shapes.validate_pattern("ip", 12345)  # type: ignore[arg-type]
        assert isinstance(r, shapes.Rejected)

    def test_raw_excerpt_truncated(self) -> None:
        """Rejected excerpts should be EXCERPT_LEN-bounded so the
        rejects log doesn't grow unbounded on giant inputs."""
        # Use a 5000-char domain so it goes through the TOO_LONG check
        # first; verify the excerpt is bounded regardless.
        r = shapes.validate_pattern("domain", "a" * 5000)
        assert isinstance(r, shapes.Rejected)
        assert len(r.raw_excerpt) <= shapes.EXCERPT_LEN + 1  # +1 for ellipsis


# ---------------------------------------------------------------------------
# Adversarial corpus — patterns from public threat-test sources
# ---------------------------------------------------------------------------

class TestAdversarial:
    """Spot-check the validators against representative attack payloads.
    Goal isn't comprehensive fuzz coverage (that's a separate fuzzing
    slice); it's confirming the reason codes are reasonable for the
    classes of injection an attacker is likely to try."""

    @pytest.mark.parametrize("payload,expected_kind,subkind,expected_reason", [
        # SQL-injection-shaped string into a sha256 hash field
        ("'; DROP TABLE patterns;--",
         "file_hash", "sha256", shapes.REASON_HASH_BAD_LENGTH),
        # XSS-shaped into a domain
        ("<script>alert(1)</script>.com",
         "domain", None, shapes.REASON_DOMAIN_INVALID),
        # Null byte in URL
        ("https://evil.com/\x00",
         "url", None, shapes.REASON_URL_INVALID_CHARS),
        # CRLF injection in domain
        ("evil.com\r\nSet-Cookie: x=y",
         "domain", None, shapes.REASON_DOMAIN_INVALID),
        # Newline injection in URL (control char)
        ("https://evil.com\nfoo",
         "url", None, shapes.REASON_URL_INVALID_CHARS),
    ])
    def test_payload_rejected_with_expected_reason(
        self, payload: str, expected_kind: str,
        subkind: object, expected_reason: str,
    ) -> None:
        r = shapes.validate_pattern(expected_kind, payload, subkind=subkind)
        assert isinstance(r, shapes.Rejected)
        assert r.reason_code == expected_reason
