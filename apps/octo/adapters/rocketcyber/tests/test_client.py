"""RocketCyberClient on the REAL client over a transport faithful to the live
API (fake_rocketcyber.py): paths, query keys, paging and its cap, the account
derivation, the three check_access outcomes, and "nothing secret in any
message".

The defect these pin: the first client read `/account/{id}`,
`/account/{id}/customers` and `/account/{id}/incidents` with `since` / `limit`
/ `order` — none of which exist. Every poll would have been a 404.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone

import pytest

from apps.octo.adapters.rocketcyber.client import (
    DEFAULT_API_URL,
    MAX_INCIDENT_PAGES,
    MAX_PAGE_SIZE,
    RocketCyberAccountError,
    RocketCyberAuthError,
    RocketCyberClientError,
    RocketCyberConfig,
    RocketCyberForbiddenError,
    RocketCyberNotFoundError,
    RocketCyberRateLimitError,
    RocketCyberRequestError,
    forbidden_guidance,
    incident_window,
    normalize_api_url,
    parse_account_id,
    poll_queries,
    recheck_range,
)
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import (
    ACCOUNT_PATH,
    API_HOST,
    API_KEY,
    API_URL,
    INCIDENTS_PATH,
    OLD_PATHS,
    PROVIDER_ID,
    SECRETS,
    FakeRocketCyberTransport,
    ago,
    incident,
    real_client,
)


def _no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


def _window() -> tuple[date, date]:
    return incident_window(datetime.now(timezone.utc), 14)


# ---------------------------------------------------------------------------
# The fake is faithful to the facts: the old paths and updatedAt are refused
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", OLD_PATHS)
def test_every_account_in_path_variant_is_a_404(path):
    transport = FakeRocketCyberTransport()
    client = real_client(transport)
    with pytest.raises(RocketCyberNotFoundError) as exc:
        client._get(path[len("/v3"):], what="probe")
    assert "API base URL" in str(exc.value)


def test_an_updated_since_filter_does_not_exist():
    transport = FakeRocketCyberTransport()
    client = real_client(transport)
    with pytest.raises(RocketCyberRequestError) as exc:
        client._get(INCIDENTS_PATH[len("/v3"):], what="incidents", params={
            "accountId": PROVIDER_ID, "updatedAt": "2026-09-01|2026-09-29",
        })
    # The vendor's words, scrubbed (typographic quotes) and bounded.
    assert "HTTP 400" in str(exc.value) and "updatedAt” is not allowed" in str(exc.value)


# ---------------------------------------------------------------------------
# The provider account
# ---------------------------------------------------------------------------

def test_provider_account_is_derived_from_the_account_path():
    transport = FakeRocketCyberTransport()
    client = real_client(transport)
    account = client.provider_account()
    assert (account.account_id, account.derived_id, account.overridden) == (
        PROVIDER_ID, PROVIDER_ID, False)
    assert account.customer_ids == (2001, 2002, 2003)
    # Paths WITHOUT an account in them; no query on the plain read.
    assert transport.calls == [("GET", ACCOUNT_PATH)]
    assert transport.queries[0] == (ACCOUNT_PATH, {})
    # Cached: the poller does not re-read it every cycle.
    client.provider_account()
    assert transport.count(ACCOUNT_PATH) == 1


def test_an_explicit_id_field_wins_over_the_path():
    transport = FakeRocketCyberTransport()
    transport.provider["accountId"] = 1000
    transport.provider["accountPath"] = "garbage"
    assert real_client(transport).provider_account().account_id == 1000


@pytest.mark.parametrize("path", [None, "", "abc", "...", 12, "900.x"])
def test_an_undeterminable_account_asks_for_the_override(path):
    transport = FakeRocketCyberTransport()
    transport.provider["accountPath"] = path
    with pytest.raises(RocketCyberAccountError) as exc:
        real_client(transport).provider_account()
    assert "Provider account ID" in str(exc.value)
    # …and with the override set, it works.
    client = real_client(transport, RocketCyberConfig(
        api_key=API_KEY, api_url=API_URL, account_id=PROVIDER_ID,
    ))
    account = client.provider_account()
    assert account.account_id == PROVIDER_ID and account.overridden
    assert account.derived_id is None


def test_the_override_is_used_even_when_the_key_names_another_account(caplog):
    transport = FakeRocketCyberTransport()
    client = real_client(transport, RocketCyberConfig(
        api_key=API_KEY, api_url=API_URL, account_id=2001,
    ))
    with caplog.at_level(logging.WARNING):
        account = client.provider_account()
    assert (account.account_id, account.derived_id) == (2001, PROVIDER_ID)
    assert "differs" in caplog.text
    start, end = _window()
    client.fetch_incidents(created_from=start, created_to=end)
    assert transport.incident_queries()[-1]["accountId"] == "2001"


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------

def test_list_customers_reads_the_details_listing():
    transport = FakeRocketCyberTransport()
    listing = real_client(transport).list_customers()
    assert [c["accountId"] for c in listing.customers] == [2001, 2002, 2003]
    assert listing.truncated is False
    assert transport.queries[-1] == (
        ACCOUNT_PATH, {"accountId": str(PROVIDER_ID), "details": "true"},
    )


def test_customers_without_a_usable_id_are_dropped():
    transport = FakeRocketCyberTransport()
    transport.customers = [
        {"accountId": 2001, "accountName": "Acme Corp", "status": "Active", "accountPath": "900.1000.2001"},
        {"accountId": "2002", "accountName": "String Id", "status": "Active", "accountPath": ""},
        {"accountId": True, "accountName": "Bool Id", "status": "Active", "accountPath": ""},
        {"accountId": 2001, "accountName": "Duplicate", "status": "Active", "accountPath": ""},
    ]
    listing = real_client(transport).list_customers()
    assert [c["accountName"] for c in listing.customers] == ["Acme Corp"]


def test_a_customer_listing_that_is_not_a_list_is_an_error():
    transport = FakeRocketCyberTransport()
    client = real_client(transport)
    client.provider_account()
    transport.force_body = {"customers": "nope"}
    transport.force_status = 200
    with pytest.raises(RocketCyberClientError):
        client.list_customers()


# ---------------------------------------------------------------------------
# Incidents: path, query, paging, cap
# ---------------------------------------------------------------------------

def test_fetch_incidents_sends_exactly_the_documented_keys():
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1), incident(2, account_id=2002, account_name="Example Bakery")]
    client = real_client(transport)
    start, end = date(2026, 9, 15), date(2026, 9, 30)
    listing = client.fetch_incidents(created_from=start, created_to=end)
    (query,) = transport.incident_queries()
    assert query == {
        "accountId": str(PROVIDER_ID),     # the PROVIDER: every customer's incidents
        "page": "1",
        "pageSize": str(MAX_PAGE_SIZE),
        "sort": "createdAt:desc",
        "createdAt": "2026-09-15|2026-09-30",
    }
    assert listing.truncated is False
    assert transport.hosts == {API_HOST}


def test_a_status_filter_is_sent_when_named_and_only_a_known_one():
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1), incident(2, status="resolved")]
    client = real_client(transport)
    start, end = _window()
    listing = client.fetch_incidents(created_from=start, created_to=end, status="resolved")
    assert transport.incident_queries()[0]["status"] == "resolved"
    assert [i["id"] for i in listing.incidents] == [5002]
    with pytest.raises(ValueError):
        client.fetch_incidents(created_from=start, created_to=end, status="closed")


def test_a_poll_cycle_names_every_status_and_reads_open_incidents_further_back():
    now = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)
    queries = poll_queries(now, window_days=14, open_lookback_days=365)
    assert [(q.status, q.created_from.isoformat(), q.created_to.isoformat()) for q in queries] == [
        ("open", "2025-09-29", "2026-09-30"),
        ("resolved", "2026-09-15", "2026-09-30"),
        ("suppressed", "2026-09-15", "2026-09-30"),
    ]
    # Never a shorter open read than the window.
    assert poll_queries(now, window_days=14, open_lookback_days=3)[0].created_from == date(2026, 9, 15)
    assert recheck_range(date(2026, 9, 1)) == (date(2026, 8, 31), date(2026, 9, 2))


def test_every_customers_incidents_come_back_through_the_provider_id():
    transport = FakeRocketCyberTransport()
    transport.incidents = [
        incident(1), incident(2, account_id=2002, account_name="Example Bakery"),
        incident(3, account_id=PROVIDER_ID, account_name="Example MSP"),
    ]
    start, end = _window()
    listing = real_client(transport).fetch_incidents(created_from=start, created_to=end)
    assert sorted(i["accountId"] for i in listing.incidents) == [PROVIDER_ID, 2001, 2002]


def test_all_pages_are_read_and_the_window_filters_by_creation_date():
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(n, created=ago(hours=n)) for n in range(1, 8)]
    transport.incidents.append(incident(99, created=ago(days=30)))    # outside
    start, end = _window()
    listing = real_client(transport).fetch_incidents(
        created_from=start, created_to=end, page_size=3,
    )
    assert [q["page"] for q in transport.incident_queries()] == ["1", "2", "3"]
    assert len(listing.incidents) == 7 and listing.total_count == 7
    assert 5099 not in {i["id"] for i in listing.incidents}
    # Newest first.
    assert [i["id"] for i in listing.incidents] == [5001, 5002, 5003, 5004, 5005, 5006, 5007]


def test_the_page_cap_stops_and_says_truncated(caplog):
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(n) for n in range(1, 11)]
    start, end = _window()
    with caplog.at_level(logging.WARNING):
        listing = real_client(transport).fetch_incidents(
            created_from=start, created_to=end, page_size=2, max_pages=3,
        )
    assert transport.count(INCIDENTS_PATH) == 3
    assert listing.truncated is True and len(listing.incidents) == 6
    # Newest first, so what a cap drops is the OLDEST part of the window.
    assert [i["id"] for i in listing.incidents] == [5001, 5002, 5003, 5004, 5005, 5006]
    assert "page cap" in caplog.text


def test_the_default_page_cap_is_the_hard_limit():
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(n, created=ago(minutes=n)) for n in range(1, 60)]
    start, end = _window()
    listing = real_client(transport).fetch_incidents(
        created_from=start, created_to=end, page_size=2,
    )
    assert transport.count(INCIDENTS_PATH) == MAX_INCIDENT_PAGES
    assert listing.truncated is True


def test_a_page_size_above_the_verified_maximum_is_never_sent():
    transport = FakeRocketCyberTransport()   # answers 400 above 500
    start, end = _window()
    real_client(transport).fetch_incidents(created_from=start, created_to=end, page_size=5000)
    assert transport.incident_queries()[0]["pageSize"] == str(MAX_PAGE_SIZE)


def test_an_incident_created_mid_drain_is_read_once():
    """Newest-first paging: a new incident pushes the rest down a slot, so
    the last item of page 1 comes again at the top of page 2 — deduplicated,
    nothing skipped."""
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(n, created=ago(hours=n)) for n in range(1, 6)]

    def _insert(page: int) -> None:
        if page == 2 and not any(i["id"] == 5100 for i in transport.incidents):
            transport.incidents.append(incident(100, created=ago(minutes=1)))

    transport.before_incidents_page = _insert
    start, end = _window()
    listing = real_client(transport).fetch_incidents(
        created_from=start, created_to=end, page_size=2,
    )
    ids = [i["id"] for i in listing.incidents]
    assert len(ids) == len(set(ids))
    assert {5001, 5002, 5003, 5004, 5005} <= set(ids)


def test_a_body_without_a_data_list_is_an_error():
    transport = FakeRocketCyberTransport()
    client = real_client(transport)
    client.provider_account()
    transport.force_status = 200
    transport.force_body = {"totalCount": 1}
    start, end = _window()
    with pytest.raises(RocketCyberClientError) as exc:
        client.fetch_incidents(created_from=start, created_to=end)
    assert "data list" in str(exc.value)


def test_redirects_are_never_followed():
    transport = FakeRocketCyberTransport()
    transport.redirect_status = 302
    with pytest.raises(RocketCyberClientError) as exc:
        real_client(transport).provider_account()
    assert "redirect" in str(exc.value)
    assert transport.hosts == {API_HOST}          # the key went nowhere else


def test_the_key_is_sent_only_as_a_bearer_header():
    transport = FakeRocketCyberTransport()
    transport.incidents = [incident(1)]
    client = real_client(transport)
    start, end = _window()
    client.fetch_incidents(created_from=start, created_to=end)
    assert set(transport.auth_headers) == {f"Bearer {API_KEY}"}
    for path, query in transport.queries:
        assert API_KEY not in path and API_KEY not in str(query)


# ---------------------------------------------------------------------------
# Status → exception
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [401, 403])
def test_a_bad_key_is_rejected_credentials(status):
    transport = FakeRocketCyberTransport()
    transport.key = "a-different-key-entirely"
    transport.reject_key_status = status
    with pytest.raises(RocketCyberAuthError) as exc:
        real_client(transport).provider_account()
    assert f"HTTP {status}" in str(exc.value)
    _no_secret(str(exc.value))


def test_a_403_on_a_data_read_is_forbidden_not_rejected():
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True
    start, end = _window()
    with pytest.raises(RocketCyberForbiddenError) as exc:
        real_client(transport).fetch_incidents(created_from=start, created_to=end)
    assert exc.value.account_id == PROVIDER_ID
    assert exc.value.vendor_error == "fixture: forbidden"


def test_a_key_revoked_after_the_account_was_read_is_rejected_not_forbidden():
    """RocketCyber answers a bad key with 403 as well as 401. Once the account
    is cached, the next 403 comes from /incidents — the key is re-checked
    against its own account before anyone is told to fix an account id."""
    transport = FakeRocketCyberTransport()
    client = real_client(transport)
    client.provider_account()
    transport.key = "the-key-was-revoked"
    transport.reject_key_status = 403
    start, end = _window()
    with pytest.raises(RocketCyberAuthError) as exc:
        client.fetch_incidents(created_from=start, created_to=end)
    assert "rejected the API key (HTTP 403)" in str(exc.value)


def test_429_carries_the_vendors_retry_after():
    transport = FakeRocketCyberTransport()
    transport.rate_limited = 1
    transport.retry_after = "120"
    with pytest.raises(RocketCyberRateLimitError) as exc:
        real_client(transport).provider_account()
    assert exc.value.retry_after_sec == 120.0
    transport.rate_limited = 1
    transport.retry_after = "999999"
    with pytest.raises(RocketCyberRateLimitError) as exc:
        real_client(transport).provider_account()
    assert exc.value.retry_after_sec == 3600.0        # bounded
    transport.rate_limited = 1
    transport.retry_after = None
    with pytest.raises(RocketCyberRateLimitError) as exc:
        real_client(transport).provider_account()
    assert exc.value.retry_after_sec is None


@pytest.mark.parametrize(
    ("knob", "value", "needle"),
    [
        ("unreachable", True, "unreachable at https://rc-api.example.test"),
        ("force_status", 503, "HTTP 503"),
        ("raw_body", b"<html>", "not JSON"),
    ],
)
def test_transport_failures(knob, value, needle):
    transport = FakeRocketCyberTransport()
    setattr(transport, knob, value)
    with pytest.raises(RocketCyberClientError) as exc:
        real_client(transport).provider_account()
    assert needle in str(exc.value)


def test_a_vendor_message_echoing_the_key_is_redacted():
    transport = FakeRocketCyberTransport()
    transport.force_status = 400
    transport.force_body = {"message": f"bad request for key {API_KEY} see https://evil.example.test/x"}
    with pytest.raises(RocketCyberRequestError) as exc:
        real_client(transport).provider_account()
    _no_secret(str(exc.value))
    assert "evil.example.test" not in str(exc.value)
    assert "[redacted]" in str(exc.value) and "[link removed]" in str(exc.value)


# ---------------------------------------------------------------------------
# check_access — which of the outcomes happened
# ---------------------------------------------------------------------------

def test_check_access_ok_performs_the_real_reads():
    transport = FakeRocketCyberTransport()
    transport.incidents = [
        incident(1), incident(2), incident(3, status="resolved"),
        incident(4, status="open", created=ago(days=40)),     # open, long ago
    ]
    check = real_client(transport).check_access()
    assert check.ok and check.account_id == PROVIDER_ID
    assert transport.count(ACCOUNT_PATH) == 2       # the account + its customers
    assert transport.count(INCIDENTS_PATH) == 3     # page 1 of each read of a cycle
    # WHICH account was picked, by name (the key's own account).
    assert f"provider account {PROVIDER_ID} (“Example MSP”, read from the API key)" in check.detail
    assert "3 customer(s)" in check.detail
    assert "3 open, and 1 resolved / 0 suppressed created in the last 14 days" in check.detail
    _no_secret(check.detail)


def test_check_access_sends_the_request_shape_the_poller_sends():
    """Test connection reads exactly what one poll cycle reads (page 1 of
    each) — the real poller's own cycle is the comparison."""
    from apps.octo.adapters.rocketcyber import RocketCyberSourceAdapter
    from apps.octo.adapters.rocketcyber.poller import RocketCyberPoller

    transport = FakeRocketCyberTransport()
    client = real_client(transport)
    assert client.check_access().ok
    probes = transport.incident_queries()
    transport.queries.clear()
    RocketCyberPoller(
        adapter=RocketCyberSourceAdapter(), client=client, sink=None,
        default_tenant_slug="_unmapped",
    )._fetch_cycle()
    assert probes == transport.incident_queries()
    assert [q["status"] for q in probes] == ["open", "resolved", "suppressed"]


def test_nothing_depends_on_what_an_unfiltered_listing_returns():
    """Were the vendor's default 'open only', an unfiltered read would never
    show a resolution. Every read names its status, so it makes no
    difference."""
    transport = FakeRocketCyberTransport()
    transport.default_status = "open"
    transport.incidents = [incident(1), incident(2, status="resolved")]
    check = real_client(transport).check_access()
    assert "1 open, and 1 resolved" in check.detail
    assert all("status" in q for q in transport.incident_queries())


def test_check_access_credentials_rejected():
    transport = FakeRocketCyberTransport()
    transport.key = "a-different-key-entirely"
    check = real_client(transport).check_access()
    assert check.outcome == "credentials_rejected" and not check.ok
    assert "rejected the API key (HTTP 401)" in check.detail
    assert transport.count(INCIDENTS_PATH) == 0


def test_check_access_forbidden_on_incidents():
    transport = FakeRocketCyberTransport()
    transport.forbid_incidents = True
    check = real_client(transport).check_access()
    assert check.outcome == "forbidden"
    assert check.detail.startswith(
        f"RocketCyber accepted the API key but refused to return data for account {PROVIDER_ID} (HTTP 403)."
    )
    assert check.detail.endswith("RocketCyber's own message: \"fixture: forbidden\"")


def test_check_access_forbidden_for_a_wrong_override_says_so():
    transport = FakeRocketCyberTransport()
    check = real_client(transport, RocketCyberConfig(
        api_key=API_KEY, api_url=API_URL, account_id=7777,
    )).check_access()
    assert check.outcome == "forbidden"
    assert "account 7777" in check.detail and "'Provider account ID' you entered" in check.detail


def test_forbidden_guidance_for_a_derived_id_names_the_override_field():
    live = forbidden_guidance(account_id=900)
    assert "Athena read account 900 from the key's own account answer" in live
    assert "'Provider account ID', then press Test connection again" in live
    assert "If it is, check in the RocketCyber console" in live
    saved = forbidden_guidance(account_id=900, saved=True)
    assert "Disable this integration, then Add integration again with that field filled in" in saved
    # Without a known id there is nothing derived to question.
    assert forbidden_guidance().endswith("is still enabled.")


def test_check_access_notes_an_override_narrower_than_the_key():
    transport = FakeRocketCyberTransport()
    check = real_client(transport, RocketCyberConfig(
        api_key=API_KEY, api_url=API_URL, account_id=2001,
    )).check_access()
    assert check.ok
    assert "the key itself belongs to account 1000" in check.detail


def test_check_access_refuses_a_derived_account_whose_customers_do_not_match():
    """The derivation took the wrong segment: polling that id would silently
    read someone else's (or no) incidents."""
    transport = FakeRocketCyberTransport()
    transport.provider["accountPath"] = "900.2001"     # ends in a CUSTOMER id
    check = real_client(transport).check_access()
    assert check.outcome == "transport"
    assert "Provider account ID" in check.detail
    assert transport.count(INCIDENTS_PATH) == 0


@pytest.mark.parametrize(
    ("knob", "value", "needle"),
    [
        ("unreachable", True, "unreachable"),
        ("force_status", 500, "HTTP 500"),
        ("rate_limited", 5, "HTTP 429"),
    ],
)
def test_check_access_transport(knob, value, needle):
    transport = FakeRocketCyberTransport()
    setattr(transport, knob, value)
    check = real_client(transport).check_access()
    assert check.outcome == "transport" and needle in check.detail
    _no_secret(check.detail)


@pytest.mark.parametrize(
    ("bad_key", "error"),
    [
        (API_KEY + "\nsecond-line-of-the-paste", "InvalidHeader"),   # requests refuses it
        (API_KEY + "\u201c", "UnicodeEncodeError"),                  # http.client cannot send it
    ],
)
def test_a_key_a_header_cannot_carry_never_escapes_and_never_rides_the_error(bad_key, error):
    """The adapter refuses such keys up front; the client still keeps its
    promises if one reaches it: check_access never raises, and no chained
    exception carries the header value (requests puts it in the message)."""
    import traceback

    transport = FakeRocketCyberTransport()
    client = real_client(transport, RocketCyberConfig(api_key=bad_key, api_url=API_URL))
    check = client.check_access()
    assert check.outcome == "transport" and error in check.detail
    with pytest.raises(RocketCyberClientError) as exc:
        client.provider_account(refresh=True)
    assert exc.value.__cause__ is None and exc.value.__suppress_context__
    rendered = "".join(traceback.format_exception(exc.value))
    assert API_KEY not in rendered and API_KEY not in check.detail


def test_check_access_against_a_wrong_base_url_says_which_url_to_use():
    transport = FakeRocketCyberTransport()
    client = real_client(transport, RocketCyberConfig(
        api_key=API_KEY, api_url=f"https://{API_HOST}/v2",
    ))
    check = client.check_access()
    assert check.outcome == "transport"
    assert "HTTP 404" in check.detail and DEFAULT_API_URL in check.detail


# ---------------------------------------------------------------------------
# Wizard input helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, DEFAULT_API_URL),
        ("", DEFAULT_API_URL),
        ("   ", DEFAULT_API_URL),
        ("https://rc-api.example.test/v3", "https://rc-api.example.test/v3"),
        ("https://rc-api.example.test/v3/", "https://rc-api.example.test/v3"),
        ("https://RC-API.example.test", "https://rc-api.example.test/v3"),
        ("https://rc-api.example.test:8443/", "https://rc-api.example.test:8443/v3"),
        ("https://[2001:db8::1]:8443/v3", "https://[2001:db8::1]:8443/v3"),
    ],
)
def test_normalize_api_url(raw, expected):
    assert normalize_api_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "http://rc-api.example.test/v3",            # the key is a bearer: https only
        "ftp://rc-api.example.test/v3",
        "https://user:pw@rc-api.example.test/v3",
        "https://rc-api.example.test/v3?x=1",
        "https://rc-api.example.test/v3#frag",
        "rc-api.example.test/v3",
        "https://[::1/v3",
    ],
)
def test_normalize_api_url_refuses_what_could_leak_the_key(raw):
    with pytest.raises(ValueError) as exc:
        normalize_api_url(raw)
    assert "pw" not in str(exc.value) and "x=1" not in str(exc.value)


@pytest.mark.parametrize(("raw", "expected"), [
    (None, None), ("", None), ("  ", None), ("1000", 1000), (" 1000 ", 1000), (1000, 1000),
])
def test_parse_account_id(raw, expected):
    assert parse_account_id(raw) == expected


@pytest.mark.parametrize("raw", ["acct-1", "-5", "0", "1.5", "１２", True, 3.0, "9" * 13])
def test_parse_account_id_refuses_non_ids(raw):
    with pytest.raises(ValueError):
        parse_account_id(raw)


def test_incident_window_is_an_inclusive_date_range_ending_tomorrow():
    now = datetime(2026, 9, 29, 23, 30, tzinfo=timezone.utc)
    assert incident_window(now, 14) == (date(2026, 9, 15), date(2026, 9, 30))
    # A non-UTC clock is converted first.
    eastern = now.astimezone(timezone(timedelta(hours=-5)))
    assert incident_window(eastern, 14) == (date(2026, 9, 15), date(2026, 9, 30))
