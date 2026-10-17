"""Who mints a webhook secret (platform vs vendor), when the platform generates
one, and where vendor-facing URLs come from (the ingest hostname only)."""
from __future__ import annotations

import pytest

from apps.octo.instances import public_urls, webhook_auth


# --- who mints the secret: platform-generated vs vendor-issued ---

def test_secret_origin_is_declared_per_field():
    assert webhook_auth.secret_origin("DATTO_WEBHOOK_SECRET") == "platform"
    assert webhook_auth.secret_origin("DATTO_JOB_OUTPUT_TOKEN") == "platform"
    assert webhook_auth.secret_origin("RESEND_WEBHOOK_SECRET") == "vendor"
    assert webhook_auth.secret_origin("DATTO_API_KEY") is None
    # Every routed vendor's field has a declaration.
    for field in webhook_auth.WEBHOOK_SECRET_FIELDS.values():
        assert field in webhook_auth.SECRET_SPECS
    assert webhook_auth.SECRET_SPECS["DATTO_WEBHOOK_SECRET"].header == "X-Webhook-Token"
    assert webhook_auth.SECRET_SPECS["RESEND_WEBHOOK_SECRET"].header is None


def test_generated_token_is_long_url_safe_and_unique():
    tokens = {webhook_auth.generate_token() for _ in range(50)}
    assert len(tokens) == 50
    for t in tokens:
        assert len(t) >= 48 and len(t) >= webhook_auth.MIN_TOKEN_LENGTH
        assert set(t) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
    # …and it passes the same create-time validation an operator's would.
    assert webhook_auth.credential_errors(
        "datto", {"DATTO_WEBHOOK_SECRET": tokens.pop()}
    ) == []


@pytest.mark.parametrize("vendor,creds,enable,expect_field", [
    ("datto", {}, True, "DATTO_WEBHOOK_SECRET"),
    ("datto", {"DATTO_WEBHOOK_SECRET": "   "}, True, "DATTO_WEBHOOK_SECRET"),
    ("datto", {}, None, None),                       # legacy caller: poll-only
    ("datto", {}, False, None),
    ("datto", {"DATTO_WEBHOOK_SECRET": "t" * 40}, True, None),  # operator's own
    ("resend", {}, True, None),                      # vendor-issued: never ours
    ("wazuh", {}, True, None),                       # no webhook route
])
def test_should_generate_only_when_asked_blank_and_platform_defined(
    vendor, creds, enable, expect_field
):
    spec = webhook_auth.should_generate(vendor, creds, enable)
    assert (spec.field if spec else None) == expect_field


def test_enabling_webhooks_never_generates_the_job_output_token():
    """That token is a separate feature (it gets embedded on endpoints); it is
    not minted as a side effect of enabling alert webhooks."""
    spec = webhook_auth.should_generate("datto", {}, True)
    assert spec is not None and spec.field != "DATTO_JOB_OUTPUT_TOKEN"


def test_webhook_choice_errors():
    err = webhook_auth.webhook_choice_errors
    assert err("datto", {}, None) == []
    assert err("datto", {}, True) == []
    assert err("datto", {}, False) == []
    assert err("datto", {"DATTO_WEBHOOK_SECRET": "t" * 40}, True) == []
    supplied = "operator-supplied-" + "z" * 30
    contradiction = err("datto", {"DATTO_WEBHOOK_SECRET": supplied}, False)
    assert len(contradiction) == 1 and supplied not in contradiction[0]
    vendor_issued = err("resend", {}, True)
    assert len(vendor_issued) == 1 and "issued by the vendor" in vendor_issued[0]
    assert err("resend", {"RESEND_WEBHOOK_SECRET": "whsec_c2FtcGxl"}, True) == []
    assert "no inbound webhook" in err("wazuh", {}, True)[0]
    assert err("wazuh", {}, False) == []


def test_too_short_message_points_at_platform_generation_not_a_shell():
    (msg,) = webhook_auth.credential_errors("datto", {"DATTO_WEBHOOK_SECRET": "short"})
    assert "let Athena generate one" in msg and "openssl" not in msg
    # Operator-facing text names the field by its wizard LABEL.
    assert msg.startswith("Webhook Token ") and "DATTO_WEBHOOK_SECRET" not in msg


# --- vendor-facing URLs: ingest hostname only ---

def test_public_ingest_base_url(monkeypatch):
    monkeypatch.setenv("OCTO_PUBLIC_BASE_URL", "https://console.example.test")
    monkeypatch.delenv("OCTO_PUBLIC_INGEST_BASE_URL", raising=False)
    assert public_urls.public_ingest_base_url() is None
    assert public_urls.webhook_url("datto") is None  # NO console fallback

    # The compose template renders an unset optional host as bare 'https://'.
    # …and a render that missed the variable leaves the literal placeholder.
    for unset in ("", "  ", "https://", "ingest.example.test", "ftp://ingest.example.test",
                  "https://${BUNDLE_PUBLIC_INGEST_HOST}"):
        monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", unset)
        assert public_urls.public_ingest_base_url() is None, unset

    monkeypatch.setenv("OCTO_PUBLIC_INGEST_BASE_URL", "https://ingest.example.test/")
    assert public_urls.public_ingest_base_url() == "https://ingest.example.test"
    assert public_urls.webhook_url("datto") == (
        "https://ingest.example.test/api/v1/webhooks/datto"
    )


def test_datto_onboarding_text_matches_the_generated_token_flow():
    from apps.octo.adapters.datto import DattoSourceAdapter

    adapter = DattoSourceAdapter()
    with_url = adapter.onboarding("https://ingest.example.test/api/v1/webhooks/datto")
    assert "shows it ONCE" in with_url.steps[0].body
    # Recovery is named by its exact click path, not by an API route.
    assert "Settings → Integrations → Datto RMM → Disable" in with_url.steps[0].body
    assert "/api/v1/" not in " ".join(s.body for s in with_url.steps)
    assert "no public ingest hostname" not in with_url.steps[2].body
    without = adapter.onboarding(None)
    assert "no public ingest hostname" in without.steps[2].body
    field = next(
        f for f in adapter.credential_shape() if f.name == "DATTO_WEBHOOK_SECRET"
    )
    assert "blank" in field.description and "openssl" not in field.description
    assert field.required is False
