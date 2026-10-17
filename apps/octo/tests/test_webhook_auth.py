"""Webhook fail-closed invariants + the operator-facing missing-secret warning."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from apps.octo.api.errors import APIError
from apps.octo.api.routers import webhooks
from apps.octo.instances import webhook_auth


class _FakeRequest:
    def __init__(self, body: bytes = b"{}", headers=None, query=None):
        self._body = body
        self.headers = headers or {}
        self.query_params = query or {}

    async def body(self) -> bytes:
        return self._body


class _AnyVendor:
    """Compares equal to every slug, so one record satisfies every route."""
    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0


def _webhook_routes():
    return [r for r in webhooks.router.routes if "POST" in getattr(r, "methods", ())]


def test_router_has_the_routes_this_guard_expects():
    # If a vendor route is added, the fail-closed guard below covers it
    # automatically — this just stops the guard silently covering nothing.
    assert {r.path for r in _webhook_routes()} >= {
        "/webhooks/resend", "/webhooks/datto", "/webhooks/datto/job-output",
    }


@pytest.mark.parametrize("route", _webhook_routes(), ids=lambda r: r.path)
def test_every_webhook_route_rejects_when_no_secret_is_configured(monkeypatch, route):
    """The invariant: NO route under /webhooks accepts an unverified request.
    Guesses in the header and the old ?token= query form change nothing."""
    record = SimpleNamespace(
        id=1, vendor_slug=_AnyVendor(), cred_ref="ref-1", default_tenant_slug="tenant-a"
    )
    monkeypatch.setattr(webhooks, "list_instances", lambda **k: [record])
    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=lambda ref: {}))
    # Anything past auth would touch these; make reaching them a loud failure.
    monkeypatch.setattr(webhooks, "SqliteIngestSink", None)
    monkeypatch.setattr(webhooks, "JobOutputStore", None)

    for request in (
        _FakeRequest(),
        _FakeRequest(headers={"x-webhook-token": "guess"}),
        _FakeRequest(query={"token": "guess"}),
    ):
        with pytest.raises(APIError) as ei:
            asyncio.run(route.endpoint(request))
        assert ei.value.code == "AUTH_INVALID"


@pytest.mark.parametrize("route", _webhook_routes(), ids=lambda r: r.path)
def test_every_webhook_route_answers_401_not_404_when_no_instance_exists(monkeypatch, route):
    """Same generic reject as a bad token: the status code must not reveal
    which integrations this deploy has configured."""
    monkeypatch.setattr(webhooks, "list_instances", lambda **k: [])
    monkeypatch.setattr(webhooks, "SqliteIngestSink", None)
    monkeypatch.setattr(webhooks, "JobOutputStore", None)

    with pytest.raises(APIError) as ei:
        asyncio.run(route.endpoint(_FakeRequest(headers={"x-webhook-token": "guess"})))
    assert ei.value.code == "AUTH_INVALID"
    assert str(ei.value) == str(webhooks._rejected())


@pytest.mark.parametrize("route", _webhook_routes(), ids=lambda r: r.path)
def test_every_webhook_route_fails_closed_when_the_vault_cannot_be_read(monkeypatch, caplog, route):
    record = SimpleNamespace(
        id=1, vendor_slug=_AnyVendor(), cred_ref="ref-1", default_tenant_slug="tenant-a"
    )

    def _boom(ref):
        raise FileNotFoundError("adapter credentials key file is missing")

    monkeypatch.setattr(webhooks, "list_instances", lambda **k: [record])
    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=_boom))
    monkeypatch.setattr(webhooks, "SqliteIngestSink", None)
    monkeypatch.setattr(webhooks, "JobOutputStore", None)

    with caplog.at_level("ERROR", logger=webhooks.logger.name):
        with pytest.raises(APIError) as ei:   # an APIError, never a bare 500
            asyncio.run(route.endpoint(_FakeRequest(headers={"x-webhook-token": "guess"})))
    assert ei.value.code == "AUTH_INVALID"
    assert "REJECTED" in caplog.text and "could not be read from the vault" in caplog.text


# --- one usability check, shared by the receiver and the warning ---

@pytest.mark.parametrize("value,usable", [
    ("whsec_" + "QUJDREVGR0hJSktMTU5PUA==", True),
    ("QUJDREVGR0hJSktMTU5PUA==", True),          # prefix is optional
    ("whsec_", False),                            # empty HMAC key
    ("whsec_!!!not-base64!!!", False),
    ("whsec_abc", False),                         # bad padding
    ("", False), ("   ", False), (None, False),
])
def test_svix_secret_usability(value, usable):
    problem = webhook_auth.secret_problem({"RESEND_WEBHOOK_SECRET": value},
                                          "RESEND_WEBHOOK_SECRET")
    assert (problem is None) is usable


def test_unusable_secret_produces_the_same_kind_of_warning_as_an_unset_one(monkeypatch):
    warnings = {}
    for label, value in (("unset", ""), ("unusable", "whsec_")):
        monkeypatch.setattr(
            webhook_auth, "credentials",
            SimpleNamespace(load=lambda ref, v=value: {"RESEND_WEBHOOK_SECRET": v}),
        )
        (warnings[label],) = webhook_auth.webhook_warnings(_rec("resend"), "Resend")
    for text in warnings.values():
        # The wizard LABEL, never the env-style credential name.
        assert "Webhook Signing Secret" in text and "rejected (401)" in text
        assert "RESEND_WEBHOOK_SECRET" not in text
        # Points at the control that exists on the instance card — by its
        # exact click path, not at a raw API route.
        assert "Settings → Integrations → Resend → Disable, then Add integration again" in text
        assert "/api/v1/" not in text
    assert "is not set" in warnings["unset"]
    assert "is set but unusable" in warnings["unusable"]


def test_receiver_and_warning_use_the_same_check(monkeypatch):
    """Whatever secret_problem says, BOTH consumers must follow."""
    monkeypatch.setattr(webhook_auth, "secret_problem", lambda creds, field: "is cursed")
    monkeypatch.setattr(webhooks, "secret_problem", webhook_auth.secret_problem)
    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=lambda ref: {}))
    monkeypatch.setattr(webhooks, "credentials", SimpleNamespace(load=lambda ref: {}))

    (warning,) = webhook_auth.webhook_warnings(_rec("datto"))
    assert "is cursed" in warning
    with pytest.raises(APIError) as ei:
        webhooks._require_secret("datto", "datto", "DATTO_WEBHOOK_SECRET",
                                 SimpleNamespace(id=1, cred_ref="ref-1"))
    assert ei.value.code == "AUTH_INVALID"


# --- create-time floor for shared tokens ---

def test_short_tokens_are_refused_at_creation_without_echoing_the_value():
    errors = webhook_auth.credential_errors("datto", {
        "DATTO_WEBHOOK_SECRET": "hunter2-hunter2",
        "DATTO_JOB_OUTPUT_TOKEN": "a",
    })
    assert len(errors) == 2
    assert all("too short" in e and str(webhook_auth.MIN_TOKEN_LENGTH) in e for e in errors)
    assert not any("hunter2" in e for e in errors)


def test_acceptable_blank_and_other_vendor_credentials_pass():
    ok = "t" * webhook_auth.MIN_TOKEN_LENGTH
    assert webhook_auth.credential_errors("datto", {"DATTO_WEBHOOK_SECRET": ok}) == []
    # Blank = poll-only: allowed (the instance is created with a warning).
    assert webhook_auth.credential_errors("datto", {"DATTO_WEBHOOK_SECRET": "  "}) == []
    assert webhook_auth.credential_errors("datto", {}) == []
    # A vendor's rules never apply to another vendor's fields.
    assert webhook_auth.credential_errors("wazuh", {"DATTO_WEBHOOK_SECRET": "a"}) == []
    assert webhook_auth.credential_errors("resend", {"RESEND_WEBHOOK_SECRET": "whsec_"}) != []


def test_existing_short_token_still_works_but_warns(monkeypatch):
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test")
    monkeypatch.setattr(webhook_auth, "credentials",
                        SimpleNamespace(load=lambda ref: {"DATTO_WEBHOOK_SECRET": "tok-legacy-9"}))
    (warning,) = webhook_auth.webhook_warnings(_rec("datto"))
    assert "shorter than" in warning and "tok-legacy-9" not in warning


# --- operator-facing warning ---

def _rec(slug: str, **config):
    return SimpleNamespace(vendor_slug=slug, cred_ref="ref-1", instance_config=config)


@pytest.mark.parametrize("slug,field", sorted(webhook_auth.WEBHOOK_SECRET_FIELDS.items()))
def test_warning_names_the_field_when_secret_missing(monkeypatch, slug, field):
    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=lambda ref: {field: " "}))
    (warning,) = webhook_auth.webhook_warnings(_rec(slug))
    assert webhook_auth.field_label(field) in warning and "rejected" in warning
    assert field not in warning


@pytest.mark.parametrize("slug,field", sorted(webhook_auth.WEBHOOK_SECRET_FIELDS.items()))
def test_no_warning_when_secret_set(monkeypatch, slug, field):
    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test")
    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=lambda ref: {field: "x" * 32}))
    assert webhook_auth.webhook_warnings(_rec(slug)) == []
    assert webhook_auth.webhook_notes(_rec(slug)) == []


@pytest.mark.parametrize("slug,field", sorted(webhook_auth.WEBHOOK_SECRET_FIELDS.items()))
def test_armed_but_unreachable_warns(monkeypatch, slug, field):
    """A usable secret with no ingest hostname: webhooks are on and can never
    arrive. The card has to say so, not just the wizard."""
    monkeypatch.delenv("OCTO_PUBLIC_INGEST_BASE_URL", raising=False)
    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=lambda ref: {field: "x" * 32}))
    (warning,) = webhook_auth.webhook_warnings(_rec(slug), "Vendor X")
    assert "no public ingest hostname" in warning and "Vendor X" in warning
    assert "docker-compose.yml" in warning and "x" * 32 not in warning


def test_explicit_poll_only_is_a_note_and_never_opens_the_vault(monkeypatch):
    def _boom(ref):
        raise AssertionError("poll-only by choice: nothing to check")

    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=_boom))
    rec = _rec("datto", webhooks="off")
    assert webhook_auth.webhook_warnings(rec, "Datto RMM") == []
    (note,) = webhook_auth.webhook_notes(rec, "Datto RMM")
    assert "off by choice" in note
    assert "Settings → Integrations → Datto RMM → Disable, then Add integration again" in note
    # Unknown / legacy values are not a recorded choice.
    assert webhook_auth.webhook_notes(_rec("datto", webhooks="maybe")) == []
    assert webhook_auth.webhook_notes(_rec("wazuh", webhooks="off")) == []


def test_spec_labels_match_what_the_wizard_shows():
    """Operator-facing text names a field by its label — so the label here
    must BE the label the adapter's credential form renders."""
    import importlib

    shown = {}
    for module, cls in (
        ("apps.octo.adapters.datto.adapter", "DattoSourceAdapter"),
        ("apps.octo.adapters.resend.adapter", "ResendSourceAdapter"),
    ):
        adapter = getattr(importlib.import_module(module), cls)()
        shown.update({f.name: f.label for f in adapter.credential_shape()})
    for field in webhook_auth.WEBHOOK_SECRET_FIELDS.values():
        assert webhook_auth.field_label(field) == shown[field]


def test_vendor_without_a_webhook_route_never_loads_credentials(monkeypatch):
    def _boom(ref):
        raise AssertionError("credentials must not be decrypted for this vendor")

    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=_boom))
    assert webhook_auth.webhook_warnings(_rec("wazuh")) == []


def test_unreadable_credentials_warn_instead_of_breaking_the_page(monkeypatch):
    def _boom(ref):
        raise ValueError("bad cred_ref")

    monkeypatch.setattr(webhook_auth, "credentials", SimpleNamespace(load=_boom))
    (warning,) = webhook_auth.webhook_warnings(_rec("datto"))
    assert "could not be read" in warning
