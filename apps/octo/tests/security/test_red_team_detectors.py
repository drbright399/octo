"""Red-team round 1 (2026-10-09), detector findings: each case that slipped
through, and the visibly-fake neighbour that must stay quiet."""
from __future__ import annotations

import base64

import pytest

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes


def _names(text: str) -> set[str]:
    return {h.detector for h in sp.find_hits(text)}


def _secret(text: str) -> bool:
    return any(h.secret for h in sp.find_hits(text))


# --------------------------------------------------------------------------- #
# Generated passwords full of , ; & = $ in named slots (finding 1)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("template", [
    'AUTOTASK_SECRET = "{v}"',       # .py
    "AUTOTASK_SECRET='{v}'",         # .sh
    'password: "{v}"',               # YAML
    'client_secret = "{v}"',
])
def test_generated_passwords_with_symbols_are_found(template):
    missed = [v for v in fakes.passwords("rt-" + template, 400) if not _secret(template.format(v=v))]
    assert missed == []


def test_symbol_heavy_and_dollar_leading_values_are_found():
    body = fakes.rand("rt-sym", 14)
    for value in (body[:6] + "&" + body[6:] + "*4", "$" + body + "&q", "$" + body,
                  "{" + body + ";x", "<" + body + ",", "%" + body[:3] + "%" + body):
        assert "vendor-credential" in _names(f'AUTOTASK_SECRET = "{value}"'), value


@pytest.mark.parametrize("line", [
    'conn_string = "Server=db;User Id=svc;Database=app"',
    'DATABASE_OPTIONS = "sslmode=require"',
    'token_format = "tok1=10:viewer:client_a:sess1,tok2=12:admin:client_b:sess2"',
    'api_key = "${DATTO_API_KEY}"',
    'TOKEN="$HOME/.config/athena/token"',
    'password = "$securePassword"',
    'DATTO_API_KEY = "{{ secrets.DATTO_API_KEY }}"',
    'api_key = "{prefix}-{env}"',
    'api_key = "<your-api-key>"',
    'secret: "[REDACTED]"',
    r'password_store = "%APPDATA%\Vendor\agent"',
    "token: --accent-colour",
    "api_key = settings.datto.api_key",
])
def test_structured_and_template_values_stay_quiet(line):
    assert not _secret(line), line


# --------------------------------------------------------------------------- #
# Dash-grouped license keys (finding 9)
# --------------------------------------------------------------------------- #

def test_dash_grouped_license_keys_are_found():
    for i in range(60):
        upper = fakes.license_key(f"rt-lk-{i}")
        if not any(c.isdigit() for c in upper):
            continue  # an all-letter key reads as an UPPER-KEBAB constant
        assert _secret(f"agent.exe --license_key {upper}"), upper
        assert _secret(f'LICENSE_KEY = "{upper}"'), upper
        lower = fakes.license_key(f"rt-lkl-{i}", groups=6, alphabet="abcdefghijklmnopqrstuvwxyz0123456789")
        assert _secret(f'license_key = "{lower}"'), lower


def test_kebab_and_constant_names_are_not_keys():
    for line in ('license_key = "LICENSE-KEY-NAME"', 'api_key = "READ-ONLY-USER"',
                 "--token GITHUB_TOKEN", 'token_type = "x86-64"'):
        assert not _secret(line), line


# --------------------------------------------------------------------------- #
# Multi-line, escaped and HTML assignments; upper-case keys (finding 10)
# --------------------------------------------------------------------------- #

def test_values_on_the_next_line_escaped_or_in_html_are_found():
    v = fakes.rand("rt-ml", 24)
    assert "vendor-credential" in _names(f'DATTO_API_SECRET = (\n    "{v}"\n)')
    assert "secret-assignment" in _names(f"datto:\n  api_secret: >-\n    {v}\n")
    assert "secret-assignment" in _names(f"datto:\n  api_secret: |\n    {v}\n")
    assert "vendor-credential" in _names(f'"source": ["DATTO_API_SECRET = \\"{v}\\"\\n"]')
    assert "html-secret-field" in _names(f'<input type="hidden" name="api_key" value="{v}">')
    assert "html-secret-field" in _names(f'<input value="{v}" type="hidden" name="client_secret">')


def test_upper_case_and_digit_keys_are_found_without_a_name():
    key = fakes.rand("rt-ud", 32, fakes.UPPER_DIGITS)
    text = f'DattoConfig(\n    URL,\n    "{fakes.rand("rt-ud2", 20, fakes.UPPER_DIGITS)}",\n    "{key}",\n)'
    assert "high-entropy-string" in _names(text)
    ulid = "01" + fakes.rand("rt-ulid", 24, "0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    assert _names(f"event_id = {ulid}") == set()  # a ULID is an id


# --------------------------------------------------------------------------- #
# Digest context is the value's own name, not a substring (finding 11)
# --------------------------------------------------------------------------- #

FERNET = base64.urlsafe_b64encode(fakes.key_bytes("rt-fernet")).decode()


@pytest.mark.parametrize("text", [
    f'SHARED_KEY = "{FERNET}"',
    f'WEBHOOK_SHARED_KEY = "{FERNET}"',
    '{"version": 2, "k": "' + FERNET + '"}',
    f'tree = load(); key = "{FERNET}"',
    f"Rotated key committed: {FERNET}",
])
def test_digest_words_elsewhere_do_not_hide_a_key(text):
    assert "fernet-or-base64-key" in _names(text)


def test_named_digests_stay_quiet():
    digest = fakes.rand("rt-digest", 64, fakes.HEX)
    for text in (f'"sha256": "{digest}"', f"fileSha256 = '{digest}'",
                 f'sha256_hex = "{digest}"', f"Hash: {digest}",
                 f"assert h.hexdigest() == (\n    \"{digest}\"\n)",
                 f'"integrity": "sha512-{fakes.rand("rt-sri", 86)}=="'):
        assert _names(text) == set(), text


# --------------------------------------------------------------------------- #
# False positives that push people to --no-verify (finding 13)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("line", [
    "DATTO_API_KEY=${DATTO_API_KEY:?missing}",
    "      DATTO_API_SECRET: ${DATTO_API_SECRET:?required}",
    "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?required}",
    "TOKEN=${TOKEN:+set}",
    "export const useFleetDeviceStatusQueryV2Options = () => ({});",
])
def test_required_variables_and_identifiers_are_not_secrets(line):
    assert _names(line) == set(), line


def test_a_real_default_inside_a_parameter_expansion_is_still_found():
    assert "secret-assignment" in _names("POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-"
                                         + fakes.rand("rt-default", 20) + "}")


def test_ids_in_url_paths_are_not_secrets_but_webhook_urls_are():
    # Every agent commit carries a session URL trailer: an id, not a credential.
    assert _names("Claude-Session: https://claude.ai/code/session_" + fakes.rand("rt-sess", 24)) == set()
    assert _names("https://drive.google.com/file/d/" + fakes.rand("rt-drive", 33) + "/view") == set()
    hook = ("https://discord.com/api/webhooks/" + fakes.rand("rt-did", 18, "0123456789") + "/"
            + fakes.rand("rt-dtok", 68, fakes.URLSAFE))
    assert "high-entropy-string" in _names(hook)
    bot = ("https://api.telegram.org/bot" + fakes.rand("rt-tg", 10, "0123456789") + ":"
           + fakes.rand("rt-tgt", 35, fakes.URLSAFE) + "/sendMessage")
    assert "telegram-bot-token" in _names(bot)  # named since the 2026-10-15 sweep


def test_an_indented_digest_list_under_a_digest_header_is_not_secret():
    rows = "".join(f"   model-{i} q4        {fakes.rand(f'rt-model-{i}', 64, fakes.HEX)}\n" for i in range(3))
    assert _names("1. manifest.json: sha256 pinned for the models:\n" + rows) == set()
    assert "hex-secret" in _names("1. the keys we issued:\n" + rows)


def test_git_shas_checksum_tables_and_expected_digests_are_not_secrets():
    sha = fakes.rand("rt-sha", 40, fakes.HEX)
    md5 = fakes.rand("rt-md5", 32, fakes.HEX)
    assert _names(f"Reverted to {sha} after the review.") == set()
    assert _names(f"cherry-pick {sha}") == set()
    table = f"| File | MD5 |\n|---|---|\n| agent.msi | {md5} |\n"
    assert _names(table) == set()
    assert _names(f'expected = "{fakes.rand("rt-exp", 64, fakes.HEX)}"') == set()
    # a hex key with no digest name in front of it is still a finding
    assert "hex-secret" in _names(f"| agent.msi | {md5} |")
    assert "hex-secret" in _names(f'API_TOKEN_VALUE = "{md5}"') | _names(f"token {md5}")


# --------------------------------------------------------------------------- #
# Job-output redaction misses (finding 8)
# --------------------------------------------------------------------------- #

KEY = fakes.rand("rt-redact", 32)


@pytest.mark.parametrize("text", [
    f"    LicenseKey    REG_SZ    {KEY}",
    f"    InstallToken    REG_EXPAND_SZ    {KEY}",
    f"AccountKey      : {KEY}",
    f"OrgKey          : {KEY}",
    f"HuntressAgent.exe /ACCT_KEY={KEY} /ORG_KEY=acme /S",
    f"agent --key {KEY[:16]}",
    f"agent --license {KEY[:16]}",
    f"agent.exe --license_key -{KEY[:20]}",
    '{\\"api_key\\": \\"' + KEY + '\\"}',
    f'<password type="clear">{KEY}</password>',
])
def test_redaction_scrubs_the_shapes_that_slipped(text):
    out, n = sp.redact(text)
    assert n >= 1 and KEY[:16] not in out and KEY[-8:] not in out, out


def test_redaction_takes_a_bare_value_to_the_next_blank():
    tail = fakes.rand("rt-tail", 10)
    out, n = sp.redact(f"password=abc&{tail} next")
    assert out == "password=[REDACTED:secret-assignment] next" and n == 1


def test_redaction_follows_a_format_list_wrap():
    key = fakes.rand("rt-wrap", 32)
    text = ('Name     : RocketAgent\n'
            'PathName : "C:\\Program Files\\Rocket\\agent.exe" --license_key ' + key[:12] + "\n"
            "           " + key[12:] + " --mode service\n"
            "State    : Running\n")
    out, n = sp.redact(text)
    assert key[:12] not in out and key[12:] not in out
    assert "--mode service" in out and "State    : Running" in out and n == 1
    assert sp.redact(out) == (out, 0)


def test_redaction_leaves_flags_paths_and_registry_keys():
    for text in ("svc.exe --password --mode service", "agent -LicenseKey -Force",
                 "RegistryKey : HKLM\\SOFTWARE\\Vendor\\Agent", "agent --ssh-key ~/.ssh/id_ed25519.pub",
                 "SortKey : 3"):
        out, n = sp.redact(text)
        assert n == 0 and out == text, text


# --------------------------------------------------------------------------- #
# The new paths stay linear on hostile input
# --------------------------------------------------------------------------- #

_HEX = fakes.rand("rt-perf-hex", 32, fakes.HEX)
_HOSTILE = {
    "md-table": "| File | MD5 |\n|---|---|\n" + ("| a | " + _HEX + " |\n") * 5000,
    "continuations": "PathName : v\n" + (" " * 11 + "z\n") * 15000,
    "wrapped-keys": ("PathName : x --license_key " + "k" * 60 + "\n" + " " * 11 + "z" * 60 + "\n") * 1300,
    "dollar-brace": 'token = "' + "${" * 100_000,
    "kv-list": 'conn_str = "' + "a=b;" * 50_000 + '"',
    "reg-lines": ("    LicenseKey    REG_SZ    " + "a" * 30 + "\n") * 3300,
    "html-inputs": '<input name="api_key" ' * 9000,
    "digest-list": "sha256 pinned:\n" + ("   m  " + _HEX * 2 + "\n") * 2800,
}


@pytest.mark.parametrize("name", sorted(_HOSTILE))
def test_hostile_input_stays_fast(name):
    import time
    text = _HOSTILE[name]
    start = time.monotonic()
    sp.find_hits(text, publish=True)
    sp.redact(text)
    assert time.monotonic() - start < 3.0
