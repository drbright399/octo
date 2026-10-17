"""Secret-shaped values for the guardrail tests, built at runtime.

Nothing in this file is a literal secret: each value is assembled from split
prefixes and a generator seeded by its label, so this file passes the scanner
it feeds, and every run sees the same values.
"""
from __future__ import annotations

import base64
import json
import random
import string

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
HEX = "0123456789abcdef"
URLSAFE = ALNUM + "-_"
# A typical password generator's symbol set (no quotes, no backslash, no space).
SYMBOLS = ALNUM + "!@#$%^&*()-_=+[]{};:,.<>?"


def passwords(label: str, n: int, length: int = 20) -> list[str]:
    """``n`` generated passwords from :data:`SYMBOLS`."""
    rng = random.Random(f"secret-guardrails:{label}")
    return ["".join(rng.choice(SYMBOLS) for _ in range(length)) for _ in range(n)]


def license_key(label: str, groups: int = 4, size: int = 4, alphabet: str = UPPER_DIGITS) -> str:
    """X7KQ-9MPL-3RTZ-8WNB style: equal dash groups."""
    return "-".join(rand(f"{label}-{i}", size, alphabet) for i in range(groups))


def rand(label: str, n: int, alphabet: str = ALNUM) -> str:
    rng = random.Random(f"secret-guardrails:{label}")
    return "".join(rng.choice(alphabet) for _ in range(n))


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(payload: dict) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps(payload).encode())
    return f"{header}.{body}.{rand('jwt-sig', 43, URLSAFE)}"


def bitlocker() -> str:
    rng = random.Random("secret-guardrails:bitlocker")
    return "-".join(f"{rng.randrange(1000, 65535) * 11:06d}" for _ in range(8))


def key_bytes(label: str, n: int = 32) -> bytes:
    rng = random.Random(f"secret-guardrails:{label}")
    return bytes(rng.randrange(256) for _ in range(n))


def ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def ticket(year: int, month: int, day: int, seq: int, prefix: str = "T") -> str:
    """An Autotask-shaped ticket number, built at run time (only the
    fixture T20000101.0001 may appear literally)."""
    return f"{prefix}{year:04d}{month:02d}{day:02d}.{seq:04d}"


PEM_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"
PEM_FOOTER = "-----END RSA " + "PRIVATE KEY-----"
LICENSE_KEY = rand("license", 32, HEX)


def positives() -> dict[str, str]:
    """detector name -> a text that must produce that finding."""
    return {
        "private-key": f"{PEM_HEADER}\n{rand('pem1', 64, ALNUM + '+/')}\n{PEM_FOOTER}",
        "age-secret-key": "AGE-SECRET" + "-KEY-1" + rand("age", 58, UPPER_DIGITS),
        "aws-access-key-id": "id = " + "AK" + "IA" + rand("aws", 16, UPPER_DIGITS),
        "github-token": "token: " + "gh" + "p_" + rand("gh", 36),
        "slack-token": "xo" + "xb-" + rand("sl1", 12, string.digits) + "-" + rand("sl2", 24),
        "slack-webhook": "https://hooks.slack.com/" + "services/T" + rand("sw1", 8, UPPER_DIGITS)
                         + "/B" + rand("sw2", 8, UPPER_DIGITS) + "/" + rand("sw3", 24),
        "anthropic-key": "sk-" + "ant-api03-" + rand("ant", 48),
        "openai-style-key": "s" + "k-proj-" + rand("oai", 48),
        "resend-key": "r" + "e_" + rand("re1", 8) + "_" + rand("re2", 24),
        "stripe-key": "sk" + "_live_" + rand("stripe", 24),
        "google-api-key": "AI" + "za" + rand("google", 35),
        "tailscale-key": "tskey" + "-auth-" + rand("ts1", 12) + "-" + rand("ts2", 30),
        "jwt": "auth=" + jwt({"sub": rand("sub", 12), "iat": 1760000000}),
        "fernet-token": "v1:" + "gAAAA" + "A" + rand("fernet", 90, URLSAFE),
        "bitlocker-recovery-key": "Password:\n    " + bitlocker(),
        "windows-product-key": "-".join(rand(f"pk{i}", 4, string.ascii_uppercase) + str(i)
                                        for i in range(5)),
        "url-credentials": "postgres://svc:" + rand("url", 16) + "@db.internal:5432/app",
        "bearer-token": "Authorization: Bearer " + rand("bearer", 40),
        "basic-auth-header": "Authorization: Basic "
                             + base64.b64encode(("svc:" + rand("basic", 18)).encode()).decode(),
        "url-query-secret": "GET /v1/devices?api_key=" + rand("query", 32) + "&page=2",
        "cli-secret-flag": r'"C:\Program Files\Agent\agent.exe" --license_key ' + LICENSE_KEY,
        "xml-secret-element": "<keyMaterial>" + rand("wifi-xml", 16) + "</keyMaterial>",
        "html-secret-field": '<input type="hidden" name="api_key" value="' + rand("html", 24) + '">',
        "registry-secret-value": "    LicenseKey    REG_SZ    " + rand("reg", 32),
        "wifi-key-content": "    Key Content            : " + rand("wifi", 14),
        "vendor-credential": "DATTO_API_KEY=" + rand("datto", 24),
        "secret-assignment": "client_secret = '" + rand("cs", 32) + "'",
        "high-entropy-string": "data " + rand("blob", 48),
        "hex-secret": "value " + rand("hex", 40, HEX),
        "fernet-or-base64-key": "k " + base64.urlsafe_b64encode(key_bytes("fernet-key")).decode(),
        "cli-password": "ssh" + "pass -p '" + rand("cli-pw", 14, SYMBOLS.replace("'", "")) + "' ssh admin@host",
    }


def negatives() -> dict[str, str]:
    """detector name -> a visibly fake value of the same shape: no finding."""
    return {
        "private-key": f"{PEM_HEADER}\nFAKE\n{PEM_FOOTER}",
        "age-secret-key": "AGE-SECRET" + "-KEY-1" + "X" * 58,
        "aws-access-key-id": "id = " + "AK" + "IA" + "IOSFODNN7EXAMPLE",
        "github-token": "gh" + "p_" + "x" * 36,
        "slack-token": "xo" + "xb-" + "0" * 12 + "-" + "x" * 24,
        "slack-webhook": "https://hooks.slack.com/" + "services/TXXXXXXXX/BXXXXXXXX/" + "X" * 24,
        "anthropic-key": "sk-" + "ant-REPLACE_ME_WITH_YOUR_KEY",
        "openai-style-key": "s" + "k-your-openai-key-goes-here",
        "resend-key": "r" + "e_123456_" + "x" * 24,
        "stripe-key": "sk" + "_live_" + "0" * 24,
        "google-api-key": "AI" + "za" + "X" * 35,
        "tailscale-key": "tskey" + "-auth-" + "xxxxxx-" + "x" * 20,
        "jwt": "auth=" + jwt({"sub": "fixture"}),
        "fernet-token": "gAAAA" + "A" + "A" * 60,
        "bitlocker-recovery-key": "-".join(["123456"] * 8),
        "windows-product-key": "-".join(["XXXXX"] * 5),
        "url-credentials": "https://user:password@example.com/x",
        "bearer-token": "Authorization: Bearer your-token-goes-here-1234",
        "basic-auth-header": "Authorization: Basic " + base64.b64encode(b"user:password").decode(),
        "url-query-secret": "GET /v1/devices?api_key=YOUR_API_KEY_HERE",
        "cli-secret-flag": "agent.exe --license_key <LICENSE_KEY>",
        "xml-secret-element": "<password>changeme123</password>",
        "html-secret-field": '<input type="hidden" name="api_key" value="{{ form.api_key }}">',
        "registry-secret-value": "    LicenseKey    REG_SZ    <none>",
        "wifi-key-content": "    Key Content            : <redacted>",
        "vendor-credential": "DATTO_API_KEY=${DATTO_API_KEY}",
        "secret-assignment": "client_secret = 'your-client-secret'",
        "high-entropy-string": "data ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789",
        "hex-secret": "value " + "0123456789abcdef" * 3,
        "fernet-or-base64-key": "k " + "A" * 43 + "=",
        "cli-password": "ssh" + 'pass -p "$SSHPASS" ssh admin@host',
    }


def redact_only_positives() -> dict[str, str]:
    """Redact-only detectors (job output, not code): what each must scrub."""
    return {
        "cli-key-flag": "agent.exe --key " + rand("cli-key", 20),
        "key-named-value": "AccountKey      : " + rand("acct-key", 32),
    }


def publish_positives() -> dict[str, str]:
    """Publish-only detectors: not secrets, never in a public copy."""
    return {
        "ip-private": "ssh " + ip(10, 20, 30, 40),
        "ip-tailnet": "peer " + ip(100, 101, 102, 103),
        "ip-public": "egress " + ip(93, 184, 216, 34),
        "tailnet-ipv6": "addr " + "fd7a:115c:" + "a1e0::1",
        "tailnet-name": "https://host.tail1234." + "ts.net/",
        "home-path": "cd /ho" + "me/alice/work",
        "memory-link": "see [" + "[feedback_vault_rules]" + "]",
        "memory-path": "see ../../../.cla" + "ude/projects/-ho" + "me-alice/memory/feedback_vault_rules.md",
        "email-address": "ops" + "@" + "corp-mail.co",
        "psa-ticket-id": "see ticket " + ticket(2026, 10, 15, 6),
    }


def publish_negatives() -> dict[str, str]:
    return {
        "ip-private": "range 10.0.0.0/8 and doc host 192.0.2.10",
        "ip-tailnet": "MagicDNS 100.100.100.100",
        "ip-public": "doc 203.0.113.5 and 198.51.100.7; resolver 1.1.1.1",
        "tailnet-ipv6": "addr fd00::1",
        "tailnet-name": "any *.ts.net name",
        "home-path": "cd /home/<user>/work",
        "memory-link": "if [[ -f x ]]; then",
        "memory-path": "skills in ~/.claude/skills/, slug -home-<user>, flag --home-dir, note feedback_vault_rules.md",
        "email-address": "mail ops@example.com",
        "psa-ticket-id": "fixture ticket T20000101.0001",
    }
