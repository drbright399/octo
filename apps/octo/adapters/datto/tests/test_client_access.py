"""DattoClient — the three outcomes (credentials rejected / authenticated but
forbidden / transport) on the REAL client over a fake transport, plus the
"nothing secret in any message" guarantee."""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

import pytest

from apps.octo.adapters.datto.client import (
    MAX_PAGE_SIZE,
    MAX_VENDOR_ERROR_CHARS,
    DattoAuthError,
    DattoClientError,
    DattoConfig,
    DattoForbiddenError,
    _scrub,
    forbidden_guidance,
)
from apps.octo.adapters.datto.poller import _RETRY_NOTE
from apps.octo.adapters.datto.tests.fake_datto import (
    ACCESS_TOKEN,
    API_KEY,
    API_SECRET,
    API_URL,
    FORBIDDEN_QUOTED,
    FORBIDDEN_TEXT_SHOWN,
    SECRETS,
    TOKEN_PATH,
    FakeDattoTransport,
    real_client,
)
from apps.octo.instances.vendor_contact import MAX_DETAIL_CHARS


def _no_secret(text: str) -> None:
    for secret in SECRETS:
        assert secret not in text


# ---------------------------------------------------------------------------
# check_access — which of the three happened
# ---------------------------------------------------------------------------

def test_check_access_ok_performs_real_data_reads():
    transport = FakeDattoTransport()
    check = real_client(transport).check_access()
    assert check.ok and check.outcome == "ok"
    # Authorization was verified by reading, not inferred from the token.
    assert transport.count("/api/v2/account") == 1
    assert transport.count("/api/v2/account/sites") == 1
    assert transport.count("/api/v2/account/alerts/open") == 1


def test_check_access_sends_the_request_shape_the_poller_sends():
    """Production: Test connection probed with max=1 and passed, then every
    real poll (max=500) was refused with HTTP 400. The probe and the poll now
    build the same query, inside the vendor's page limit."""
    transport = FakeDattoTransport()
    client = real_client(transport)
    assert client.check_access().ok
    client.fetch_alerts_since("2026-01-01T00:00:00.000Z", max_results=500)
    probe, poll = transport.alert_queries
    assert set(probe) == set(poll) == {"max", "sortBy", "order", "after"}
    assert probe["max"] == poll["max"] == str(MAX_PAGE_SIZE)


def test_check_access_credentials_rejected():
    transport = FakeDattoTransport()
    transport.token_status = 401
    check = real_client(transport).check_access()
    assert check.outcome == "credentials_rejected" and not check.ok
    assert "rejected credentials" in check.detail
    # No data read is attempted without a token.
    assert transport.count("/api/v2/account") == 0


def test_check_access_authenticated_but_forbidden():
    """Production: the token is issued, then EVERY data endpoint answers 403."""
    transport = FakeDattoTransport()
    transport.forbid_data = True
    check = real_client(transport).check_access()
    assert check.outcome == "forbidden" and not check.ok
    assert check.vendor_error == FORBIDDEN_TEXT_SHOWN
    assert transport.count(TOKEN_PATH) == 1     # authentication itself worked
    # Operator-actionable, and it quotes the vendor's own words — LAST, as a
    # labelled quotation, never inside the instruction.
    assert "Datto accepted the API key" in check.detail
    assert "(HTTP 403)" in check.detail and check.detail.endswith(FORBIDDEN_QUOTED)
    assert "Setup > Users" in check.detail and "API Security Level" in check.detail
    _no_secret(check.detail)


@pytest.mark.parametrize("status", [500, 502, 404])
def test_check_access_unexpected_status_is_transport(status):
    transport = FakeDattoTransport()
    transport.data_status = status
    check = real_client(transport).check_access()
    assert check.outcome == "transport"
    assert f"HTTP {status}" in check.detail


def test_check_access_unreachable_is_transport_and_never_raises():
    transport = FakeDattoTransport()
    transport.unreachable = True
    check = real_client(transport).check_access()
    assert check.outcome == "transport"
    assert "unreachable" in check.detail and "ConnectionError" in check.detail


def test_ping_still_answers_a_bool(caplog):
    transport = FakeDattoTransport()
    assert real_client(transport).ping() is True
    transport.forbid_data = True
    with caplog.at_level(logging.DEBUG):
        assert real_client(transport).ping() is False
    _no_secret(caplog.text)


# ---------------------------------------------------------------------------
# Data calls raise the specific exception
# ---------------------------------------------------------------------------

def test_forbidden_is_its_own_exception_on_every_data_call():
    transport = FakeDattoTransport()
    transport.forbid_data = True
    client = real_client(transport)
    with pytest.raises(DattoForbiddenError) as alerts_exc:
        client.fetch_alerts_since("2026-01-01T00:00:00.000Z")
    with pytest.raises(DattoForbiddenError) as sites_exc:
        client.list_sites()
    assert alerts_exc.value.vendor_error == FORBIDDEN_TEXT_SHOWN
    assert alerts_exc.value.resource == "/api/v2/account/alerts/open"
    assert sites_exc.value.resource == "/api/v2/account/sites"
    # Pre-existing `except DattoClientError` callers keep working…
    assert isinstance(alerts_exc.value, DattoClientError)
    # …and it is never confused with a rejected key.
    assert not isinstance(alerts_exc.value, DattoAuthError)
    _no_secret(str(alerts_exc.value))


def test_rejected_key_raises_auth_error_from_data_calls():
    transport = FakeDattoTransport()
    transport.token_status = 403     # …with an OAuth error body = bad key pair
    with pytest.raises(DattoAuthError):
        real_client(transport).fetch_alerts_since("2026-01-01T00:00:00.000Z")


@pytest.mark.parametrize("body", [b"<html>blocked</html>", {}, ["x"], {"error": {"n": 1}}])
def test_a_bare_403_from_the_token_endpoint_is_not_rejected_credentials(body):
    """Datto answers 403 while it temporarily blocks an IP that kept going
    after HTTP 429. Reading that as "the key pair is dead" told the operator
    to Disable + re-add (mappings and webhook token lost) for something that
    clears by itself."""
    transport = FakeDattoTransport()
    transport.token_status = 403
    transport.token_error_body = body
    client = real_client(transport)
    with pytest.raises(DattoClientError) as exc:
        client.fetch_alerts_since("2026-01-01T00:00:00.000Z")
    assert not isinstance(exc.value, DattoAuthError)
    assert "rate limiting" in str(exc.value)
    assert client.check_access().outcome == "transport"


def test_stale_token_is_refreshed_once_and_the_read_succeeds():
    transport = FakeDattoTransport()
    transport.alerts = [{"alertUid": "a-1"}]
    transport.stale_token_once = True
    alerts = real_client(transport).fetch_alerts_since("2026-01-01T00:00:00.000Z")
    assert alerts == [{"alertUid": "a-1"}]
    assert transport.count(TOKEN_PATH) == 2


def test_forbidden_drops_the_cached_token_so_a_fix_is_picked_up():
    transport = FakeDattoTransport()
    transport.forbid_data = True
    client = real_client(transport)
    with pytest.raises(DattoForbiddenError):
        client.list_sites()
    transport.forbid_data = False        # operator fixed the security level
    assert client.list_sites() == transport.sites
    assert transport.count(TOKEN_PATH) == 2


def test_non_json_body_is_a_transport_error_not_a_crash():
    transport = FakeDattoTransport()
    transport.raw_data_body = b"<html>gateway</html>"
    with pytest.raises(DattoClientError, match="not JSON"):
        real_client(transport).list_sites()


# ---------------------------------------------------------------------------
# Vendor text is scrubbed and bounded before anything can surface it
# ---------------------------------------------------------------------------

def test_vendor_error_echoing_secrets_is_scrubbed_and_bounded():
    transport = FakeDattoTransport()
    transport.forbid_data = True
    transport.forbidden_body = {
        "status": 403,
        "error": (
            f"user {API_KEY} with secret {API_SECRET} and bearer {ACCESS_TOKEN} "
            "plus eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl "
            "may not\nread\tthis\x00resource " + "x " * 4000
        ),
    }
    client = real_client(transport)
    check = client.check_access()
    assert check.outcome == "forbidden"
    assert len(check.vendor_error) <= MAX_VENDOR_ERROR_CHARS
    assert "[redacted]" in check.vendor_error
    assert "eyJhbGci" not in check.vendor_error
    assert "\n" not in check.vendor_error and "\x00" not in check.vendor_error
    _no_secret(check.vendor_error)
    _no_secret(check.detail)
    with pytest.raises(DattoForbiddenError) as exc:
        client.list_sites()
    _no_secret(str(exc.value))


@pytest.mark.parametrize("body", [b"not json", ["a", "list"], {"error": {"nested": 1}}, {}])
def test_forbidden_without_a_usable_error_string_still_gives_guidance(body):
    transport = FakeDattoTransport()
    transport.forbid_data = True
    transport.forbidden_body = body
    check = real_client(transport).check_access()
    assert check.outcome == "forbidden" and check.vendor_error == ""
    # No access-denied text from the vendor → the cause is NOT asserted: it
    # may be the temporary rate-limit block, which needs no change at all.
    assert "HTTP 403 without saying why" in check.detail
    assert "rate limiting" in check.detail and "Setup > Users" in check.detail
    assert "Datto's own message" not in check.detail


def test_credentials_pasted_into_the_api_url_never_reach_a_message():
    transport = FakeDattoTransport()
    transport.unreachable = True
    config = DattoConfig(
        api_url="https://alice:hunter2-fixture@datto-api.example.test/?k=hunter3-fixture",
        api_key=API_KEY, api_secret_key=API_SECRET,
    )
    check = real_client(transport, config).check_access()
    assert check.outcome == "transport"
    assert "hunter2-fixture" not in check.detail and "hunter3-fixture" not in check.detail
    # The message names the API origin — parsed, not substring-matched: the
    # exact scheme + host, with no userinfo, path or query left on it.
    shown = re.search(r"unreachable at (\S+?):\s", check.detail)
    assert shown is not None, check.detail
    origin = urlsplit(shown.group(1))
    assert (origin.scheme, origin.hostname, origin.port) == ("https", "datto-api.example.test", None)
    assert origin.username is None and origin.password is None
    assert origin.path == "" and origin.query == "" and origin.fragment == ""


def test_a_secret_that_is_not_token_shaped_is_still_redacted():
    """Every other fixture secret is 24+ chars of [A-Za-z0-9-], which the
    token-shape regex masks by itself. A secret with punctuation (or a short
    one) is covered ONLY by the explicit known-secret replacement."""
    odd_secret = "fixture!secret#pw"            # 17 chars, outside the regex class
    transport = FakeDattoTransport()
    transport.forbid_data = True
    transport.forbidden_body = {
        "status": 403, "error": f"secret {odd_secret} of key abc may not read this",
    }
    client = real_client(transport, DattoConfig(
        api_url=API_URL, api_key=API_KEY, api_secret_key=odd_secret,
    ))
    check = client.check_access()
    assert check.outcome == "forbidden" and "[redacted]" in check.vendor_error
    assert odd_secret not in check.vendor_error and odd_secret not in check.detail
    with pytest.raises(DattoForbiddenError) as exc:
        client.list_sites()
    assert odd_secret not in str(exc.value)
    # Threshold pinned: a value under 8 chars is not treated as a secret
    # (replacing every "abc" would shred ordinary prose).
    assert "abc" in check.vendor_error
    assert _scrub("the abc key", ["abc"]) == "the abc key"


def test_vendor_text_cannot_close_its_quotation_or_carry_a_link():
    """A hostile endpoint's `error` used to be spliced into the instruction
    sentence inside single quotes it could close, so its text read as
    Athena's own voice — on the admin card and in status_detail."""
    transport = FakeDattoTransport()
    transport.forbid_data = True
    transport.forbidden_body = {"status": 403, "error": (
        "'). SESSION EXPIRED - re-enter your Datto secret at "
        "https://evil.example.test/a or www.evil.example.test \"now\" `ok`"
    )}
    check = real_client(transport).check_access()
    assert "evil.example.test" not in check.detail and "://" not in check.detail
    assert check.detail.count("[link removed]") == 2
    for straight in ("'", '"', "`"):
        assert straight not in check.vendor_error
    # The platform's instruction is intact and comes first; the vendor's words
    # are one labelled, unclosable quotation at the very end.
    instruction, _, said = check.detail.partition(" Datto's own message: ")
    assert instruction == forbidden_guidance("x").partition(" Datto's own message: ")[0]
    assert said == f'"{check.vendor_error}"' and "SESSION EXPIRED" in said


def test_guidance_never_tells_a_saved_integration_to_regenerate_its_key():
    wizard = forbidden_guidance("denied")
    saved = forbidden_guidance("denied", saved=True, retry_note=_RETRY_NOTE)
    assert "Do NOT regenerate the API keys" in saved
    assert "Test connection again" in wizard and "do not regenerate" in wizard
    for text in (wizard, saved):
        assert "regenerate or keep" not in text
        assert "API Security Level" in text and "Generate API Keys" in text
    # The longest variant fits the status_detail bound UNCUT.
    longest = forbidden_guidance(
        "x" * MAX_VENDOR_ERROR_CHARS, saved=True, retry_note=_RETRY_NOTE,
    )
    assert len(longest) <= MAX_DETAIL_CHARS
    assert len(forbidden_guidance("", saved=True, retry_note=_RETRY_NOTE)) <= MAX_DETAIL_CHARS


# ---------------------------------------------------------------------------
# Redirects are never followed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_a_redirect_from_the_api_host_is_an_error_not_a_second_request(status):
    transport = FakeDattoTransport()
    client = real_client(transport)
    client.authenticate()
    transport.redirect_status = status
    with pytest.raises(DattoClientError, match="redirect"):
        client.list_sites()
    check = client.check_access()
    assert check.outcome == "transport" and "redirect" in check.detail
    assert "internal.example.test" not in check.detail
    assert transport.hosts == {"datto-api.example.test"}


def test_a_redirect_on_the_token_endpoint_never_resends_the_key_pair():
    transport = FakeDattoTransport()
    transport.redirect_status = 307          # 307 re-sends the POST body
    with pytest.raises(DattoClientError, match="redirect") as exc:
        real_client(transport).authenticate()
    assert not isinstance(exc.value, DattoAuthError)
    assert transport.hosts == {"datto-api.example.test"}
    assert len([b for b in transport.bodies if API_SECRET in b]) == 1
