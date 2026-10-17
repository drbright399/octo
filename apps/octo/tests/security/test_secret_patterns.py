"""The shared detectors: each one fires on a real-looking value, stays quiet on a
visibly fake one, masks without revealing, and redacts job output.

The second half covers the 2026-10-15 sweep upgrade: the new shapes, the
lockfile e-mail exemption, NUL-bearing text and long lines, the local-block
prefilter, ``--all-history`` and the hooks running the strict ``--publish``
checks. Every value is built at run time, so this file passes the scanner."""
from __future__ import annotations

import base64
import importlib.util
import json
import random
import re
import subprocess
import sys
import time

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes
from apps.octo.tests.security.conftest import REPO_ROOT, SCANNER

_SPEC = importlib.util.spec_from_file_location("scan_sensitive", SCANNER)
ss = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("scan_sensitive", ss)  # dataclasses resolve their module by name
_SPEC.loader.exec_module(ss)

B64_KEY = base64.b64encode(fakes.key_bytes("sweep-wg")).decode()          # WireGuard style
URL_KEY = base64.urlsafe_b64encode(fakes.key_bytes("sweep-fernet")).decode()  # Fernet style
HEX6 = "3f" + "9a1c"
UUID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _cf_token(secret: str) -> str:
    body = {"a": fakes.rand("sweep-cf-a", 32, fakes.HEX), "t": UUID, "s": secret}
    return base64.b64encode(json.dumps(body).encode()).decode().rstrip("=")


# The shapes the 2026-10-15 sweep found missing or only generically covered.
SWEEP_POSITIVES = {
    "webhook-signing-secret": "signing: whsec_" + base64.b64encode(fakes.key_bytes("sweep-whsec", 24)).decode(),
    "itglue-api-key": "key ITG." + fakes.rand("sweep-itg1", 32, fakes.HEX) + "."
                      + fakes.rand("sweep-itg2", 64, fakes.URLSAFE),
    "telegram-bot-token": "bot" + fakes.rand("sweep-tg-id", 10, "123456789") + ":"
                          + fakes.rand("sweep-tg", 35, fakes.URLSAFE),
    "cloudflare-tunnel-token": "cloudflared tunnel run --tok" + "en " + _cf_token(B64_KEY),
    "labelled-secret": "    Signing key: " + fakes.rand("sweep-label", 32),
}
SWEEP_NEGATIVES = {
    "webhook-signing-secret": "signing: whsec_" + _b64("not-a-real-signing-secret-fixture"),
    "itglue-api-key": "key ITG." + "0123456789abcdef" * 2,
    "telegram-bot-token": "bot" + "123456789:" + "X" * 35,
    "cloudflare-tunnel-token": "run " + _cf_token("not-a-real-tunnel-secret"),
    "labelled-secret": "    Signing key: <your-signing-key>",
}
SWEEP_PUBLISH_POSITIVES = {
    "nextdns-profile-id": "upstream https://dns.nextdns.io/" + HEX6,
    "url-path-token": "dashboard https://rmm.vendor.invalid/dashboard/" + fakes.rand("sweep-deep", 21),
}
SWEEP_PUBLISH_NEGATIVES = {
    "nextdns-profile-id": "upstream https://dns.nextdns.io/abc123 and colour #" + HEX6,
    "url-path-token": "fonts https://fonts.gstatic.com/s/inter/v13/" + fakes.rand("sweep-font", 40) + ".woff2",
}

POSITIVES = {**fakes.positives(), **SWEEP_POSITIVES}
NEGATIVES = {**fakes.negatives(), **SWEEP_NEGATIVES}
PUBLISH_POSITIVES = {**fakes.publish_positives(), **SWEEP_PUBLISH_POSITIVES}
PUBLISH_NEGATIVES = {**fakes.publish_negatives(), **SWEEP_PUBLISH_NEGATIVES}


def _names(text: str, *, publish: bool = False, path: str = "") -> set[str]:
    return {h.detector for h in sp.find_hits(text, sp.Context(path=path), publish=publish)}


def _detectors(findings) -> list[str]:
    return [f.detector for f in findings]


def test_every_secret_detector_has_a_positive_and_a_negative():
    redact_only = {d.name for d in sp.DETECTORS if not d.scan}
    # putty-private-key has its own test; ip-address reports under ip-*.
    reported = set(sp.REPORTED_NAMES) - sp.PUBLISH_ONLY_NAMES - {"putty-private-key"} - redact_only
    assert reported <= set(POSITIVES) and reported <= set(NEGATIVES)
    assert sp.PUBLISH_ONLY_NAMES <= set(PUBLISH_POSITIVES) and sp.PUBLISH_ONLY_NAMES <= set(PUBLISH_NEGATIVES)
    assert redact_only == set(fakes.redact_only_positives())


def test_reported_and_publish_only_name_sets():
    assert sp.PUBLISH_ONLY_NAMES == {
        "ip-private", "ip-public", "ip-tailnet", "tailnet-ipv6", "tailnet-name", "home-path",
        "memory-path", "memory-link", "email-address", "nextdns-profile-id", "url-path-token",
        "psa-ticket-id",
    }
    families = {n for n in sp.DETECTOR_NAMES if n.startswith("cli-password:")}
    assert len(families) >= 15  # guardrails v6: one detector per option shape
    assert sp.REPORTED_NAMES == (set(sp.DETECTOR_NAMES) - {"ip-address"} - families
                                 | {"hex-secret", "ip-private", "ip-public", "ip-tailnet", "cli-password"})
    sweep = {"webhook-signing-secret", "itglue-api-key", "telegram-bot-token",
             "cloudflare-tunnel-token", "fernet-or-base64-key", "labelled-secret"}
    assert sweep <= sp.REPORTED_NAMES - sp.PUBLISH_ONLY_NAMES
    assert "cli-password" in sp.REPORTED_NAMES - sp.PUBLISH_ONLY_NAMES  # guardrails v5
    assert len(sp.DETECTOR_NAMES) == len(set(sp.DETECTOR_NAMES))  # names are priorities
    assert "ip-address" not in sp.REPORTED_NAMES and not families & sp.REPORTED_NAMES
    assert all(d.reported == ("cli-password",) for d in sp.DETECTORS if d.name in families)


@pytest.mark.parametrize("name", sorted(fakes.redact_only_positives()))
def test_redact_only_detectors_scrub_job_output_but_never_block_a_commit(name):
    text = fakes.redact_only_positives()[name]
    out, n = sp.redact(text)
    assert n == 1 and f"[REDACTED:{name}]" in out
    assert name not in _names(text)


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_detector_fires_on_a_real_looking_value(name):
    assert name in _names(POSITIVES[name])


@pytest.mark.parametrize("name", sorted(NEGATIVES))
def test_detector_ignores_a_visibly_fake_value(name):
    assert _names(NEGATIVES[name]) == set()


@pytest.mark.parametrize("name", sorted(PUBLISH_POSITIVES))
def test_publish_detector_fires_only_in_publish_mode(name):
    text = PUBLISH_POSITIVES[name]
    assert name in _names(text, publish=True)
    assert _names(text) == set()  # not a secret: only the --publish checks report it


@pytest.mark.parametrize("name", sorted(PUBLISH_NEGATIVES))
def test_publish_detector_ignores_documentation_values(name):
    assert _names(PUBLISH_NEGATIVES[name], publish=True) == set()


def test_putty_private_key():
    ppk = ("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: k\n"
           "Public-Lines: 2\n" + fakes.rand("ppk1", 64) + "\n" + "Private" + "-Lines: 1\n")
    assert "putty-private-key" in _names(ppk)
    assert _names("Convert it to a PuTTY-User-Key-File- format first.") == set()


def test_vendor_names_by_name_not_shape():
    # A username is low-entropy, yet an Autotask API username with a value is a credential.
    text = 'AUTOTASK_USERNAME: "apiuser' + fakes.rand("at-user", 4, "0123456789") + '@corp-mail.co"'
    assert "vendor-credential" in _names(text)
    code = "AUTOTASK_INTEGRATION_CODE=" + fakes.rand("at-code", 27, fakes.UPPER_DIGITS)
    assert "vendor-credential" in _names(code)
    assert _names('creds = {"DATTO_JOB_OUTPUT_TOKEN": "s3cret"}') == set()  # leet fixture
    assert _names("NEXTDNS_API_KEY = os.environ['NEXTDNS_API_KEY']") == set()


def test_code_expressions_are_not_values():
    for line in (
        "api_key = credentials.get('api_key')",
        "password = _find_password(payload, PASSWORD_KEYS)",
        "credentials: HTTPAuthorizationCredentials | None = Depends(bearer)",
        "token = secrets.token_urlsafe(32)",
        "secret_b32 = pyotp.random_base32()",
        "currentPassword: currentPw,",
        "{ max: 75, token: \"--accent\", pulse: false }",
        "Format: 'token=operator_id:role:tenant:session_id,token2=...'",
    ):
        assert _names(line) == set(), line


def test_a_secret_nested_in_a_rejected_candidate_is_still_found():
    conn = 'conn_string = "Server=db;User Id=svc;Password=' + fakes.rand("conn", 20) + ';"'
    assert "secret-assignment" in _names(conn)


def test_digests_are_not_secrets():
    digest = fakes.rand("digest", 64, fakes.HEX)
    assert _names(f'"sha256": "{digest}"') == set()
    assert _names(f"{digest}  package-lock.json") == set()  # sha256sum listing
    assert _names(f"assert h.hexdigest() == (\n    \"{digest}\"\n)") == set()
    assert _names("id = 1b4e28ba-2fa1-11d2-883f-0016d3cca427") == set()  # a UUID


def test_placeholder_heuristics():
    for fake in ("changeme", "your-api-key", "${TOKEN}", "<token>", "%API_KEY%", "xxxxxxxx",
                 "fixture-key-123", "s3cret", "hunter2", "__ATHENA_TOKEN__", "test-token-abcdef"):
        assert sp.looks_placeholder(fake) or not sp.looks_real(fake), fake
    assert sp.looks_real(fakes.rand("real", 24))


def test_mask_never_reveals_the_value():
    value = fakes.rand("mask", 40)
    masked = sp.mask(value)
    assert value not in masked and masked.endswith("(40)") and masked.startswith(value[:4])
    assert sp.mask("abc12345") == "***(8)"


# --------------------------------------------------------------------------- #
# redaction (job output)
# --------------------------------------------------------------------------- #

def test_redact_license_key_command_line():
    line = (r'"C:\Program Files\RocketAgent\agent.exe" --license_key '
            f"{fakes.LICENSE_KEY} --mode service")
    out, n = sp.redact(line)
    assert fakes.LICENSE_KEY not in out and n == 1
    assert "--license_key [REDACTED:cli-secret-flag] --mode service" in out


@pytest.mark.parametrize("form", [
    "--license_key={v}", "--license-key {v}", "-LicenseKey {v}", "/LicenseKey:{v}",
    "--token '{v}'", "-Password {v}",
])
def test_redact_cli_flag_forms(form):
    value = fakes.rand("cli-" + form, 20)
    out, n = sp.redact("svc.exe " + form.format(v=value))
    assert value not in out and n == 1 and "[REDACTED:cli-secret-flag]" in out


@pytest.mark.parametrize("name", sorted(set(POSITIVES) - {"high-entropy-string", "hex-secret",
                                                         "fernet-or-base64-key"}))
def test_redact_scrubs_every_shaped_secret(name):
    # fernet-or-base64-key is scan-only, like high-entropy-string: in job
    # output a bare 32-byte base64 value is as likely a file hash.
    out, n = sp.redact(POSITIVES[name])
    assert n >= 1 and "[REDACTED:" in out


def test_redact_redacts_even_weak_values_in_secret_slots():
    # Scan precision does not apply: a weak real password is still a password.
    out, n = sp.redact("password=changeme")
    assert out == "password=[REDACTED:secret-assignment]" and n == 1


def test_redact_keeps_triage_evidence():
    digest = fakes.rand("evidence", 64, fakes.HEX).upper()
    text = (f"Algorithm Hash Path\nSHA256    {digest} C:\\ProgramData\\x.exe\n"
            "powershell.exe -EncodedCommand " + fakes.rand("enc", 60) + "\n"
            "PasswordLastSet : 1/2/2026\nTokenType : Bearer\n")
    out, n = sp.redact(text)
    assert out == text and n == 0


def test_redact_is_idempotent_and_handles_empty():
    once, n1 = sp.redact(POSITIVES["bearer-token"])
    twice, n2 = sp.redact(once)
    assert twice == once and n1 == 1 and n2 == 0
    assert sp.redact("") == ("", 0)


def test_redact_private_key_block_and_bitlocker():
    out, _ = sp.redact("before\n" + POSITIVES["private-key"] + "\nafter")
    assert out == "before\n[REDACTED:private-key]\nafter"
    out, _ = sp.redact(POSITIVES["bitlocker-recovery-key"])
    assert fakes.bitlocker() not in out


# --------------------------------------------------------------------------- #
# 2026-10-15 sweep: new shapes and contexts
# --------------------------------------------------------------------------- #

def test_whsec_webhook_signing_secrets():
    for body in (base64.b64encode(fakes.key_bytes("sw-svix", 24)).decode(),  # Svix / Resend
                 fakes.rand("sw-stripe", 32)):                               # Stripe
        assert "webhook-signing-secret" in _names("RESEND_WEBHOOK_SECRET=" + json.dumps("whsec_" + body))
        assert "webhook-signing-secret" in _names(f"secret whsec_{body} rotated")
    for fake in ("whsec_" + _b64("sample-key-sample-key-sample"),  # decodes to fixture text
                 "whsec_" + _b64("ABCDEFGHIJKLMNOPQRSTUVWX"),      # decodes to the alphabet
                 "whsec_" + "A" * 32, "whsec_c2FtcGxl"):
        assert _names(fake) == set(), fake


@pytest.mark.parametrize("text", [
    f'ENV = "ADAPTER_CREDENTIALS_KEY_BASE64={URL_KEY}\\n"',  # NAME=value inside a string
    f"X_KEY_BASE64={URL_KEY}",                                 # a name no keyword covers
    f"key {URL_KEY}",                                          # no name at all
    f'f"FERNET={URL_KEY}"',
    f"[Interface]\nPrivateKey = {B64_KEY}\n",                  # WireGuard
    f"wg_private: {B64_KEY}",
])
def test_32_byte_base64_keys_are_found_with_or_without_a_key_name(text):
    assert "fernet-or-base64-key" in _names(text)


def test_32_byte_base64_placeholders_digests_and_public_keys_stay_quiet():
    cert = ("-----BEGIN CERTIFICATE-----\n" + fakes.rand("sw-cert", 64, fakes.ALNUM + "+/") + "\n"
            + B64_KEY + "\n-----END CERTIFICATE-----\n")
    for text in (
        "k " + "A" * 43 + "=",                          # zero bytes
        "k " + _b64("this-is-only-32-bytes-of-text!!!"),  # readable text
        f"[Peer]\nPublicKey = {B64_KEY}\n",              # a WireGuard public key
        f'"sha256": "{B64_KEY}"',                        # a named digest
        f"golang.example/mod v1.2.3 h1:{B64_KEY}",      # go.sum
        cert,                                           # a certificate line
    ):
        assert "fernet-or-base64-key" not in _names(text), text
    assert "fernet-or-base64-key" not in _names(B64_KEY[:-2] + "x=")  # not canonical: no 32-byte value
    # generated files (lockfiles, bundles, source maps) carry hashes, not keys
    assert ss.scan_text("web/package-lock.json", "k " + URL_KEY + "\n") == []


def test_wifi_and_unifi_secret_names():
    for text in (
        "WPA_PSK=" + fakes.rand("sw-psk", 16),
        "  x_passphrase: " + fakes.rand("sw-pp", 14),
        '"x_iapp_key": "' + fakes.rand("sw-iapp", 32, fakes.HEX) + '"',
        '"x_ipsec_pre_shared_key": "' + fakes.rand("sw-ipsec", 20) + '"',
        "const wpaPsk = '" + fakes.rand("sw-camel", 16) + "';",
        "Environment=WIFI_PSK=" + fakes.rand("sw-systemd", 18),   # systemd, unquoted
        "    psk " + "= " + fakes.rand("sw-ini", 18),
    ):
        assert "secret-assignment" in _names(text), text
    for text in ("psk: ${WIFI_PSK}", "WPA_PSK=", "x_passphrase: <your-passphrase>",
                 "upskill_level = '" + fakes.rand("sw-upskill", 16) + "'"):
        assert "secret-assignment" not in _names(text), text


def test_secret_labels_in_prose_and_docstrings():
    v = fakes.rand("sw-prose", 28)
    for text in (f"Signing key: {v}", f"    Encryption key = {v}", f"Pre-shared key: {v}",
                 f"Integration code: {v}", f"API key: `{v}`"):
        assert "labelled-secret" in _names(text), text
    for text in ("Signing key: rotated monthly", "API key: see the vault entry",
                 "Encryption key = HMAC-SHA256", "The license key: required",
                 "Signing key: <your-signing-key>"):
        assert _names(text) == set(), text


def test_itglue_telegram_and_cloudflare_tunnel_tokens():
    assert "itglue-api-key" in _names("ITGLUE_API_KEY=ITG." + fakes.rand("sw-itg", 40))
    assert _names("see https://api.itglue.example/docs and ITG.") == set()
    tg = fakes.rand("sw-tg-id", 9, "123456789") + ":AA" + fakes.rand("sw-tg2", 33, fakes.URLSAFE)
    assert "telegram-bot-token" in _names("TELEGRAM_BOT_TOKEN=" + tg)
    assert "telegram-bot-token" in _names("https://api.telegram.org/bot" + tg + "/getMe")
    assert "telegram-bot-token" not in _names("robot" + tg)  # glued to a word: not one token
    token = _cf_token(B64_KEY)
    assert "cloudflare-tunnel-token" in _names("TUNNEL_TOKEN=" + token)
    assert "cloudflare-tunnel-token" in _names("  " + token + "\n")
    # base64 JSON without a / t / s, or a JWT's first segment, is not a tunnel token
    other = base64.b64encode(json.dumps({"version": 3, "file": "app.js", "names": ["a"] * 8})
                             .encode()).decode()
    assert "cloudflare-tunnel-token" not in _names("map " + other)
    assert "cloudflare-tunnel-token" not in _names(POSITIVES["jwt"])


def test_workflow_signatures_after_escaped_ampersands():
    sig = fakes.rand("sw-sig", 43, fakes.URLSAFE)
    base = ("https://prod-00.westus.logic.azure.com:443/workflows/" + fakes.rand("sw-wf", 32, fakes.HEX)
            + "/triggers/manual/paths/invoke?api-version=2016-06-01")
    for sep in ("\\u0026", "&amp;", "&"):
        text = '{"url": "' + base + sep + "sv=1.0" + sep + "sig=" + sig + '"}'
        assert "url-query-secret" in _names(text), sep
    assert _names(base + "\\u0026sig=YOUR_SIGNATURE_HERE") == set()


def test_a_query_value_with_a_json_escaped_slash_is_still_one_value():
    # PHP's json_encode writes "/" as "\/": the value goes on past it (before
    # the & change it did, and a short head alone is not a value).
    head, tail = fakes.rand("sw-esc1", 5), fakes.rand("sw-esc2", 20)
    text = '{"hook": "https:\\/\\/hooks.vendor.invalid\\/in?token=' + head + "\\/" + tail + '"}'
    assert "url-query-secret" in _names(text)
    # Any other escape still ends the value: the next parameter is its own.
    sig = fakes.rand("sw-esc3", 32)
    assert "url-query-secret" in _names('"u": "https://x.vendor.invalid/a?v=1\\u0026sig=' + sig + '"')


def test_url_path_tokens_are_found_in_vendor_deep_links_only():
    token = fakes.rand("sw-deep2", 24)
    assert "url-path-token" in _names(f"https://rmm.vendor.invalid/share/{token}?view=1", publish=True)
    assert "url-path-token" in _names(f"https://portal.vendor.invalid/login?share={token}", publish=True)
    # A Drive / Docs file id is not a secret (no hit without --publish), but a
    # link to an internal document is not public material either.
    drive = "https://drive.google.com/file/d/" + fakes.rand("sw-drive", 33) + "/view"
    assert _names(drive) == set() and _names(drive, publish=True) == {"url-path-token"}
    for url in (
        "https://fonts.googleapis.com/css2?family=Inter:wght@400;500&display=swap",
        "https://fonts.gstatic.com/s/inter/v13/" + fakes.rand("sw-font2", 40) + ".woff2",
        "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/model.gguf",
        "https://github.com/acme/widget/commit/" + fakes.rand("sw-sha", 40, fakes.HEX),
        f"https://status.vendor.invalid/incidents/{UUID}",
        "https://cdn.vendor.invalid/assets/index-" + fakes.rand("sw-hash", 16) + ".js",
        "https://claude.ai/code/session_" + fakes.rand("sw-sess", 24),
        "https://docs.vendor.invalid/api/getDeviceStatusForSiteV2",
        "https://store.vendor.invalid/blobs/sha256-" + fakes.rand("sw-sri", 30),
        "https://rmm.vendor.invalid/dashboard/YOUR_SHARE_TOKEN_HERE",
        "https://" + fakes.rand("sw-host", 20) + ".vendor.invalid/",   # a host, not a path
    ):
        assert "url-path-token" not in _names(url, publish=True), url


def test_separator_only_segments_and_odd_json_never_crash_the_scan(monkeypatch):
    # "//-----" comment banners and "=-----" table rules in a file that holds
    # a URL: a path segment with no letter or digit in it (it used to raise
    # ValueError from max() and take the hook down with a traceback).
    for text in ("// see https://docs.vendor.invalid/a\n//" + "-" * 30 + "\n",
                 "https://docs.vendor.invalid/a/" + "_" * 20 + "/b",
                 "x https://h.vendor.invalid/?q=" + "-" * 16 + "&a=1"):
        assert _names(text, publish=True) == set()
        assert ss.scan_text("web/src/x.ts", text, publish=True) == []
    # a tunnel-token candidate whose JSON nests deeper than the recursion limit
    def deep(raw):
        raise RecursionError("maximum recursion depth exceeded")
    monkeypatch.setattr(sp.json, "loads", deep)
    assert "cloudflare-tunnel-token" not in _names("TUNNEL_TOKEN=" + _cf_token(B64_KEY))
    assert sp.redact("out " + _cf_token(B64_KEY))[1] == 0


def test_nextdns_profile_ids_in_nextdns_context_only():
    for text in (f"https://dns.nextdns.io/{HEX6}", f"tls://{HEX6}.dns.nextdns.io",
                 f"NEXTDNS_PROFILE_ID={HEX6}", f'nextdns_profile: "{HEX6}"',
                 f"https://api.nextdns.io/profiles/{HEX6}/logs"):
        assert "nextdns-profile-id" in _names(text, publish=True), text
    for text in (f"color: #{HEX6}", f"commit {HEX6}", "https://dns.nextdns.io/abc123",
                 "NEXTDNS_PROFILE_ID=${NEXTDNS_PROFILE_ID}", f"profile {HEX6}"):
        assert "nextdns-profile-id" not in _names(text, publish=True), text


SWEEP_ALL = {**SWEEP_POSITIVES, **SWEEP_PUBLISH_POSITIVES}


@pytest.mark.parametrize("name", sorted(SWEEP_ALL))
def test_sweep_findings_are_masked(name):
    text = SWEEP_ALL[name]
    found = ss.scan_text("app/x.txt", text, publish=True)
    rendered = "\n".join(f.render() for f in found)
    assert name in _detectors(found)
    for hit in sp.find_hits(text, publish=True):
        assert hit.value not in rendered


# --------------------------------------------------------------------------- #
# Lockfiles: third-party author e-mails, never secrets
# --------------------------------------------------------------------------- #

LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Cargo.lock")


@pytest.mark.parametrize("lockfile", LOCKFILES)
def test_lockfile_author_emails_are_exempt_but_secrets_are_not(lockfile):
    meta = '  "license": "commercial; contact jane.doe' + "@" + 'corp-mail.co",\n'
    path = f"apps/web/{lockfile}"
    assert _detectors(ss.scan_text(path, meta, publish=True)) == []
    assert _detectors(ss.scan_text("apps/web/package.json", meta, publish=True)) == ["email-address"]
    assert _detectors(ss.scan_text(f"apps/web/my-{lockfile}", meta, publish=True)) == ["email-address"]
    assert _detectors(ss.scan_text(f"apps/web/{lockfile}.bak", meta, publish=True)) == ["email-address"]
    # the exemption is for the file's contents, never for an address in its own path
    named = "jane.doe" + "@" + f"corp-mail.co/{lockfile}"
    assert "path:email-address" in _detectors(ss.path_findings(named, None, None, publish=True))
    leak = ('  "resolved": "https://ci:' + fakes.rand("sw-lock", 20)
            + '@registry.vendor.invalid/x.tgz",\n')
    assert "url-credentials" in _detectors(ss.scan_text(path, meta + leak, publish=True))
    token = "gh" + "p_" + fakes.rand("sw-lock-gh", 36)
    assert _detectors(ss.scan_text(path, f'"token": "{token}"\n', publish=True)) == ["github-token"]
    # still publish-only elsewhere in the file: an IP is reported
    assert _detectors(ss.scan_text(path, "host " + fakes.ip(10, 1, 2, 3) + "\n", publish=True)) == ["ip-private"]


def test_the_web_lockfile_passes_the_publish_gate():
    lock = REPO_ROOT / "apps" / "athena" / "web" / "package-lock.json"
    if not lock.is_file():
        pytest.skip("no web lockfile in this checkout")
    found = ss.scan_blob("apps/athena/web/package-lock.json", lock.read_bytes(), publish=True, local=None)
    assert "email-address" not in _detectors(found)


# --------------------------------------------------------------------------- #
# Blind spots: NUL bytes in text, very long lines
# --------------------------------------------------------------------------- #

def test_utf8_text_with_a_stray_nul_is_scanned_as_text():
    token = "gh" + "p_" + fakes.rand("sw-nul", 36)
    data = b"// generated\x00\nconst x = 1;\nconst k = '" + token.encode() + b"';\n"
    decoded = ss.decode_text(data)
    assert decoded is not None and decoded[1] == "utf-8" and decoded[0].encode() == data
    found = ss.scan_blob("web/src/x.tsx", data, publish=True, local=None)
    assert [(f.line, f.detector) for f in found] == [(3, "github-token")]  # not "binary-file"
    secret = fakes.rand("sw-nul-assign", 32)
    # the value heuristics run too (binary strings only get the fixed shapes)
    assign = b"x = 0\x00\nclient_secret = '" + secret.encode() + b"'\n"
    assert "secret-assignment" in _detectors(ss.scan_blob("app/x.py", assign, publish=False, local=None))


def test_binary_with_nuls_stays_binary():
    assert ss.decode_text(b"\x00" * 600 + b"text") is None
    assert ss.decode_text(b"SQLite format 3\x00" + bytes(84) + fakes.key_bytes("sw-db", 400)) is None
    assert ss.decode_text(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + fakes.key_bytes("sw-png", 256)) is None


def test_a_value_deep_in_a_very_long_line_is_found_quickly():
    token = "gh" + "p_" + fakes.rand("sw-long", 36)
    line = "var a=" + ",".join(f"x{i}" for i in range(30000)) + f",k='{token}';\n"  # ~200k characters
    assert len(line) > 100_000
    start = time.monotonic()
    for path in ("web/dist/app.js", "web/dist/app.min.js"):  # minified: the fixed shapes still count
        found = ss.scan_text(path, line, publish=True)
        assert "github-token" in _detectors(found)
        assert token not in "\n".join(f.render() for f in found)
    assert time.monotonic() - start < 10


# --------------------------------------------------------------------------- #
# The local-block prefilter finds exactly what the full alternation finds
# --------------------------------------------------------------------------- #

def test_ascii_fold_table_matches_re_ignorecase():
    every = "".join(chr(c) for c in range(0x80, 0x110000) if not 0xD800 <= c <= 0xDFFF)
    folds = {m.group(0): a for a in "abcdefghijklmnopqrstuvwxyz" for m in re.finditer(a, every, re.I)}
    assert folds == sp.ASCII_FOLDS
    assert sp.fold_lower("\u212aELVIN \u017fECRET") == "kelvin secret"


def test_needles_never_change_what_is_found():
    # A detector with needles skips text that holds none of them; on every
    # sample (and on case-folded variants) the hits are the same without them.
    import dataclasses
    samples = [*POSITIVES.values(), *NEGATIVES.values(), *PUBLISH_POSITIVES.values(),
               *PUBLISH_NEGATIVES.values(), *fakes.redact_only_positives().values()]
    samples += [s.upper() for s in samples] + [s.replace("s", "\u017f").replace("k", "\u212a") for s in samples]
    with_needles = [sp.find_hits(s, publish=True) for s in samples]
    redacted = [sp.redact(s) for s in samples]
    original = sp.DETECTORS
    try:
        sp.DETECTORS = tuple(dataclasses.replace(d, needles=()) for d in original)
        assert [sp.find_hits(s, publish=True) for s in samples] == with_needles
        assert [sp.redact(s) for s in samples] == redacted
    finally:
        sp.DETECTORS = original
    assert any(d.needles for d in sp.DETECTORS)


def test_required_literal():
    assert ss.required_literal(r"\bzebra\s+clinic\b") == "clinic"
    assert ss.required_literal("Acme Corp") == "acme corp"
    assert ss.required_literal("foo|barbaz") == ""      # an alternation: nothing certain
    assert ss.required_literal("[a-z]+x") == ""
    assert ss.required_literal("ab") == ""              # too short to be worth it
    assert ss.required_literal("caf\u00e9-bar") == "-bar"  # non-ASCII breaks a run


GLO = "glo" + "bex"


def test_local_block_prefilter_matches_the_full_pattern(tmp_path):
    terms = ["Zebra Clinic", rf"\<{GLO}\>", r"host-[0-9]+\.corp", "(unclosed", "[[:alpha:]]*",
             "foo|barbaz", r"acme\s*corp", "caf\u00e9", "kelvin", "stra\u00dfe", "is"]
    block = tmp_path / "block"
    block.write_text("\n".join(terms) + "\n", encoding="utf-8")
    lb = ss.load_local_block(block)
    pieces = ["zebra clinic", "ZEBRA  CLINIC", "Zebra Clinic", GLO, f"{GLO}_x", f"x-{GLO.upper()}",
              "host-42.corp", "(unclosed", "barbaz", "FOO", "acmecorp", "ACME\tCORP", "caf\u00e9",
              "CAF\u00c9", "\u212aelvin", "KELVIN", "stra\u00dfe", "STRASSE", "\u0130S", "\u017fix",
              "plain words", "\u2014", "x", "\n"]
    rng = random.Random("sw-prefilter")
    for _ in range(600):
        text = " ".join(rng.choice(pieces) for _ in range(rng.randrange(1, 8)))
        assert [m.span() for m in lb.finditer(text)] == [m.span() for m in lb.pattern.finditer(text)], text
        assert (lb.search(text) is None) == (lb.pattern.search(text) is None), text
    narrow = ss.load_local_block(tmp_path / "block")
    assert narrow.search("this is it") is not None  # "is": a term too short for a literal
    block.write_text("Zebra Clinic\n", encoding="utf-8")
    assert ss.load_local_block(block).search("nothing to see here") is None


def test_local_block_prefilter_is_off_when_a_term_holds_a_back_reference(tmp_path):
    # A numbered back-reference counts groups across the whole alternation: a
    # subset of the terms renumbers them, so "(a)bcd\1" alone would match
    # "abcda" where the full pattern (whose group 1 is "(q)") does not. With a
    # back-reference in the file, every text gets the full pattern.
    block = tmp_path / "block"
    block.write_text("(q)rstu\n(a)bcd\\1\n(x)yzw\\1\n", encoding="utf-8")
    lb = ss.load_local_block(block)
    for text in ("x abcda y", "abcda qrstu", "xyzwx", "nothing here", "QRSTU ABCDA", "qrstu"):
        assert [m.span() for m in lb.finditer(text)] == [m.span() for m in lb.pattern.finditer(text)], text
        assert (lb.search(text) is None) == (lb.pattern.search(text) is None), text
    assert lb.search("qrstu") is not None
    assert ss._has_backref(r"(?P<n>zz)top(?P=n)") and ss._has_backref(r"(a)?(?(1)b|c)xyz")
    assert not ss._has_backref(r"\bacme\s+corp\b") and not ss._has_backref("host-[0-9]+")



def test_a_hit_inside_a_long_token_leaves_no_value_readable(tmp_path):
    # The history scan found it: a local-block term in a URL's host masked the
    # host only, and the long token around it (the dashboard share token in
    # its path) was then left readable in the excerpt.
    block = tmp_path / "block"
    block.write_text(GLO + "\n")
    token = fakes.rand("sw-excerpt", 21)
    line = ("{ url: 'https://" + GLO + "corp.rmm.vendor.invalid/dashboard/" + token
            + "/default-dashboard' }\n")
    for publish in (False, True):
        found = ss.scan_text("ops/server.js", line, publish=publish, local=ss.load_local_block(block))
        rendered = "\n".join(f.render() for f in found)
        assert "local-block" in _detectors(found) and token not in rendered
        assert GLO not in rendered.lower() and "default-dashboard" in rendered  # names stay readable
    rendered = "\n".join(f.render() for f in ss.scan_text(
        "t.py", f'ENV = "ADAPTER_CREDENTIALS_KEY_BASE64={URL_KEY}\\n"\n'))
    assert "ADAPTER_CREDENTIALS_KEY_BASE64=" in rendered and URL_KEY not in rendered


def test_short_value_pieces_glued_to_a_hit_stay_masked(tmp_path):
    # Alone, a 20+ character token is masked whole. Glued to a hit, its rest
    # used to be judged in pieces cut at '.', '/' and '=' (12+ only), so a
    # value split by a dot or kept short slipped through.
    block = tmp_path / "block"
    block.write_text(GLO + "\n")
    local = ss.load_local_block(block)
    a, b = fakes.rand("sw-piece-a", 10), fakes.rand("sw-piece-b", 10)
    c = fakes.rand("sw-piece-c", 9, fakes.HEX)
    for line, values in (
        (f"u = 'https://{GLO}corp.rmm.vendor.invalid/s/{a}.{b}'", [a, b]),   # dotted value
        (f"u = 'https://{GLO}.vendor.invalid/share/{a}/{b}/view'", [a, b]),  # short path pieces
        (f"k = {a}{GLO}{c}", [a, c]),                                      # a term inside a value
        (f"{GLO.upper()}_SHARE={a}", [a]),
    ):
        for publish in (False, True):
            rendered = "\n".join(f.render() for f in ss.scan_text("ops/x.js", line + "\n",
                                                                  publish=publish, local=local))
            assert "[local-block]" in rendered
            for value in values:
                assert value not in rendered, (line.replace(value, "<v>"), publish)
    # names around the hit stay readable: a host, a path word, a constant name
    rendered = "\n".join(f.render() for f in ss.scan_text(
        "ops/x.js", f"u = 'https://{GLO}corp.rmm.vendor.invalid/dashboard/settings'\n", local=local))
    assert "corp.rmm.vendor.invalid/dashboard/settings" in rendered

# --------------------------------------------------------------------------- #
# --all-history: every object the repository holds
# --------------------------------------------------------------------------- #

def _leak(label: str, name: str = "k") -> tuple[str, str]:
    token = "gh" + "p_" + fakes.rand(label, 36)
    return token, f"{name} = '{token}'\n"


def test_all_history_finds_what_no_ref_shows(make_repo):
    repo = make_repo()
    token, _ = _leak("sw-hist")
    repo.commit("a.py", "x = 1\n")
    # a dropped stash
    repo.write("stash.py", f"s = '{token}'\n")
    repo.git("add", "stash.py")
    repo.git("stash", "-q")
    repo.git("stash", "drop", "-q")
    # staged, written into a tree, unstaged: a dangling tree still names it
    repo.write("dir/tree.py", f"t = '{token}'\n")
    repo.git("add", "dir/tree.py")
    repo.git("write-tree")
    repo.git("rm", "-q", "--cached", "dir/tree.py")
    (repo.path / "dir" / "tree.py").unlink()
    # staged and unstaged with no tree: no path survives
    repo.write("lost.py", f"lost = '{token}'\n")
    lost = repo.git("hash-object", "-w", "lost.py").stdout.strip()
    (repo.path / "lost.py").unlink()
    # a commit only the reflog remembers, with the token in its message
    repo.commit("b.py", "y = 2\n", message=f"old token {token}")
    repo.git("reset", "-q", "--hard", "HEAD~1")
    # a text file with a NUL byte (git calls it binary), and an annotated tag
    (repo.path / "nul.py").write_bytes(b"x = 1\n\x00\nn = '" + token.encode() + b"'\n")
    repo.git("add", "nul.py")
    repo.git("commit", "-q", "-m", "nul")
    repo.git("tag", "-a", "v1", "-m", f"release; key {token}")

    proc = repo.scan("--all-history", "--no-local-block")
    out = proc.stdout
    assert proc.returncode == 1 and token not in out + proc.stderr
    for where in ("stash.py:1:", "dir/tree.py:1:", f"{ss.UNREACHABLE}/{lost[:12]}:1:", "nul.py:3:",
                  "<commit-message>:1:", "<tag-message>:1:"):
        assert f"{where} [github-token]" in out, where
    assert "unreachable object(s)" in proc.stderr
    # the tree and the reachable history alone show none of the lost ones
    assert repo.scan("--tree", "--no-local-block").returncode == 1  # nul.py is still there
    assert "stash.py" not in repo.scan("--range", "HEAD", "--no-local-block").stdout


def test_all_history_scans_each_blob_once_and_every_file_name(make_repo):
    repo = make_repo()
    token, leak = _leak("sw-dedup")
    repo.commit("one.py", leak)
    repo.commit("two.py", leak)            # the same blob under a second name
    repo.commit("one.py", "x = 1\n")       # gone from the tree, not from history
    named, _ = _leak("sw-name")
    repo.commit(f"notes/{named}.txt", "named after a token\n")
    repo.git("rm", "-q", f"notes/{named}.txt")
    repo.git("commit", "-q", "-m", "rm")
    proc = repo.scan("--all-history", "--no-local-block")
    out = proc.stdout
    assert proc.returncode == 1 and token not in out and named not in out
    assert len([line for line in out.splitlines() if "[github-token] col 6: k = '" in line]) == 1
    assert "[path:github-token]" in out


def test_all_history_checks_every_name_a_dropped_commit_carried(make_repo):
    # A dropped commit that only renamed: its root tree is unreachable, but
    # the directory it renamed and the blob it copied are reachable under
    # their old names, so no blob is recovered under the new ones. Those
    # names are still in the object store, and are checked like any other.
    repo = make_repo()
    repo.commit("src/a.py", "x = 1\n")
    repo.commit("b.txt", "same\n")
    dir_name, _ = _leak("sw-lost-dir")
    file_name, _ = _leak("sw-lost-file")
    repo.git("mv", "src", dir_name)               # a reachable subtree under a new name
    repo.write(f"z/{file_name}.txt", "same\n")    # a reachable blob under a second name
    repo.git("add", "-A")
    repo.git("commit", "-q", "--no-verify", "-m", "rename")
    repo.git("reset", "-q", "--hard", "HEAD~1")
    repo.git("reflog", "expire", "--expire=now", "--all")
    proc = repo.scan("--all-history", "--no-local-block")
    out = proc.stdout
    assert proc.returncode == 1 and dir_name not in out + proc.stderr and file_name not in out
    assert len([line for line in out.splitlines() if "[path:github-token]" in line]) == 2, out


def test_all_history_with_publish_and_a_clean_history(make_repo):
    repo = make_repo()
    repo.commit("docs/net.md", "gateway 192.0.2.10\n")
    proc = repo.scan("--all-history", "--no-local-block", "--publish")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    repo.commit("docs/net.md", "gateway " + fakes.ip(10, 20, 30, 40) + "\n")
    repo.commit("docs/net.md", "gateway 192.0.2.11\n")
    assert repo.scan("--all-history", "--no-local-block").returncode == 0  # not a secret
    proc = repo.scan("--all-history", "--no-local-block", "--publish")
    assert proc.returncode == 1 and "docs/net.md:1: [ip-private]" in proc.stdout


def test_all_history_on_an_empty_repository(make_repo):
    repo = make_repo()
    proc = repo.scan("--all-history", "--no-local-block")
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------------- #
# The hooks run the strict --publish checks (Rick, 2026-10-15)
# --------------------------------------------------------------------------- #

def test_the_hooks_run_the_strict_publish_checks():
    hooks = REPO_ROOT / ".githooks"
    assert re.search(r"--staged --publish\b", (hooks / "pre-commit").read_text())
    assert re.search(r'--message "\$1" --publish\b', (hooks / "commit-msg").read_text())
    pre_push = (hooks / "pre-push").read_text()
    assert re.search(r'--range "\$spec".*--publish', pre_push)
    assert re.search(r'--ref-name "\$remote_ref" --publish\b', pre_push)  # ref names too (v5)
    assert ss.GUARDRAILS_VERSION >= 5


def _agent_message(label: str) -> str:
    return ("fix(scanner): the hooks run the strict checks\n\nWhy and how.\n\n"
            "Co-Authored-By: Claude Opus 5.5 <noreply" + "@anthropic.com>\n"
            "Claude-Session: https://claude.ai/code/session_" + fakes.rand(label, 24) + "\n")


def test_an_agent_commit_message_passes_message_publish(tmp_path):
    msg = tmp_path / "COMMIT_EDITMSG"
    msg.write_text(_agent_message("sw-trailer"))
    run = [sys.executable, str(SCANNER), "--no-local-block", "--message", str(msg), "--publish"]
    proc = subprocess.run(run, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    msg.write_text("deploy to " + fakes.ip(10, 20, 30, 40) + "\n")
    proc = subprocess.run(run, capture_output=True, text=True)
    assert proc.returncode == 1 and "<commit-message>:1: [ip-private]" in proc.stdout


def test_installed_hooks_refuse_what_the_public_standard_keeps_out(make_repo):
    remote = make_repo("remote.git", bare=True)
    repo = make_repo()
    repo.install_guardrails()
    repo.git("add", "-A")
    first = repo.git("commit", "-q", "-m", "guardrails", check=False)
    assert first.returncode == 0, first.stdout + first.stderr  # the guardrails pass --publish
    repo.git("remote", "add", "origin", str(remote.path))
    lan = fakes.ip(10, 20, 30, 40)
    proc = repo.commit("docs/net.md", f"gateway {lan}\n")
    assert proc.returncode != 0 and "docs/net.md:1: [ip-private]" in proc.stdout + proc.stderr
    assert repo.commit("docs/net.md", "gateway 192.0.2.10\n").returncode == 0  # documentation range
    proc = repo.git("commit", "-q", "--allow-empty", "-m", f"note: the gateway is {lan}", check=False)
    assert proc.returncode != 0 and "<commit-message>:1: [ip-private]" in proc.stdout + proc.stderr
    proc = repo.git("commit", "-q", "--allow-empty", "-m", _agent_message("sw-hook-trailer"), check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # a commit that skipped the hooks is refused on push
    assert repo.commit("docs/home.md", "cd /ho" + "me/alice/work\n", no_verify=True).returncode == 0
    proc = repo.git("push", "-q", "origin", "main", check=False)
    assert proc.returncode != 0 and "docs/home.md:1: [home-path]" in proc.stdout + proc.stderr
    assert remote.git("rev-parse", "--verify", "-q", "refs/heads/main", check=False).returncode != 0


def test_list_detectors_names_the_new_shapes():
    proc = subprocess.run([sys.executable, str(SCANNER), "--list-detectors"], capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    for name in ("webhook-signing-secret", "itglue-api-key", "telegram-bot-token",
                 "cloudflare-tunnel-token", "fernet-or-base64-key", "labelled-secret",
                 "url-path-token (--publish)", "nextdns-profile-id (--publish)",
                 "email-address (--publish)", "binary-file (--publish)", "cli-password",
                 "psa-ticket-id (--publish)"):
        assert name in lines, name


def test_full_repo_publish_scan_is_fast():
    start = time.monotonic()
    proc = subprocess.run([sys.executable, str(SCANNER), "--tree", "--publish", "--no-local-block", "-q"],
                          cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stderr
    assert time.monotonic() - start < 30
    assert "Traceback" not in proc.stderr
