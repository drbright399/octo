"""Inbound-webhook secret bookkeeping — one table, two consumers.

The public webhook receivers (``api/routers/webhooks.py``) FAIL CLOSED: a
vendor whose instance has no USABLE webhook secret gets every inbound request
rejected. That is only safe to live with if the operator is TOLD, so the
admin read-back surfaces (instance create / list, the Integrations
aggregator) call :func:`webhook_warnings` and render whatever it returns.

Keeping the vendor → credential-field table AND the usability check here (not
in the router) means the receiver and the operator-facing warning can never
disagree about which field gates which route, or about whether its value is
good enough to verify anything.
"""
from __future__ import annotations

import base64
import binascii
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Literal, Optional

from apps.octo import credentials

logger = logging.getLogger(__name__)

# WHO MINTS the secret — the one distinction the onboarding wizard must get
# right, so it is declared per field instead of inferred:
#   platform — WE define the shared token (the vendor has no signing scheme and
#              just echoes back whatever header it is told to send). The
#              platform can generate it, so a new deployment never has to leave
#              the console to invent one.
#   vendor   — the VENDOR issues the secret when the webhook endpoint is created
#              on their side (Resend/Svix 'whsec_…'). It can only be pasted in;
#              generating one here would verify nothing.
SecretOrigin = Literal["platform", "vendor"]


@dataclass(frozen=True)
class WebhookSecretSpec:
    field: str
    # How the secret is used, which decides what "usable" means:
    #   svix  — 'whsec_' + base64 HMAC key (Resend signs with Svix)
    #   token — an opaque shared token compared in constant time
    kind: Literal["svix", "token"]
    origin: SecretOrigin
    # Header the sender presents a `token` in; None for signature schemes.
    header: Optional[str] = None
    # What the operator SEES this field called in the wizard. Operator-facing
    # text uses this, never the env-style `field` name (logs keep `field`).
    label: str = ""


# The header every shared-token route reads (`api/routers/webhooks.py`).
TOKEN_HEADER = "X-Webhook-Token"

SECRET_SPECS: dict[str, WebhookSecretSpec] = {
    spec.field: spec
    for spec in (
        WebhookSecretSpec(
            "RESEND_WEBHOOK_SECRET", "svix", "vendor",
            label="Webhook Signing Secret",
        ),
        WebhookSecretSpec(
            "DATTO_WEBHOOK_SECRET", "token", "platform", TOKEN_HEADER,
            label="Webhook Token",
        ),
        # Platform-defined too, but NOT minted by "enable real-time webhooks":
        # it authorizes the quick-job output relay, a separate feature whose
        # token ends up embedded on endpoints. Nothing generates it until an
        # operator asks for that feature by name.
        WebhookSecretSpec(
            "DATTO_JOB_OUTPUT_TOKEN", "token", "platform", TOKEN_HEADER,
            label="Job Output Token",
        ),
    )
}

# vendor_slug → the credential field that authenticates its inbound webhook.
# A vendor appears here iff `api/routers/webhooks.py` has a route for it.
WEBHOOK_SECRET_FIELDS: dict[str, str] = {
    "resend": "RESEND_WEBHOOK_SECRET",
    "datto": "DATTO_WEBHOOK_SECRET",
}

_FIELD_KINDS: dict[str, str] = {f: spec.kind for f, spec in SECRET_SPECS.items()}

# Platform-generated tokens: 48 random bytes → 64 url-safe characters (384
# bits), comfortably above MIN_TOKEN_LENGTH and safe in any header value.
GENERATED_TOKEN_BYTES = 48

# Floor for operator-chosen shared tokens, enforced when an instance is
# created. These guard session-less public routes whose only other brake is a
# rate limiter, so the token must be infeasible to guess: 32 characters of
# hex is 128 bits, of base64/url-safe text ~190 — what any password manager
# produces. Anything a person would type from memory is shorter than this.
# (Tokens the platform generates itself are far longer: GENERATED_TOKEN_BYTES.)
MIN_TOKEN_LENGTH = 32

# Where the operator goes to act on a warning. Credentials are create-only, so
# the fix is always: disable the instance, create a corrected one. Every piece
# of text that describes that recovery names the SAME control, which exists on
# the instance card (console: pages/settings/integrations.tsx).
RECOVERY_PATH = "Settings → Integrations → {vendor} → Disable, then Add integration again"


def recovery_path(vendor_name: str = "") -> str:
    """The exact click path for disable → re-create, naming the vendor card."""
    return RECOVERY_PATH.format(vendor=vendor_name or "<vendor>")


def replace_hint(vendor_name: str = "") -> str:
    return (
        "Credentials are create-only. To replace one: "
        f"{recovery_path(vendor_name)}."
    )


REPLACE_HINT = replace_hint()

# instance_config key recording the operator's explicit answer to "real-time
# webhooks?" at create time. Absent on legacy rows (choice unknown).
WEBHOOK_CHOICE_KEY = "webhooks"

POLL_ONLY_NOTE = (
    "Poll-only: real-time webhooks are off by choice. To turn them on: "
    "{path}."
)


def field_label(field: str) -> str:
    """The wizard label for a webhook-secret field (falls back to the name)."""
    spec = SECRET_SPECS.get(field)
    return spec.label if spec and spec.label else field


def configured_secret(creds: dict[str, Any], field: str) -> str:
    """The stripped secret value, or "" when missing/blank/non-string."""
    value = creds.get(field)
    return value.strip() if isinstance(value, str) else ""


def svix_key(secret: str) -> Optional[bytes]:
    """The HMAC key inside a Svix secret, or None when there isn't a usable
    one. 'whsec_' alone decodes to an EMPTY key, which anyone can forge
    against — that is unusable, not a secret."""
    key_part = secret.split("_", 1)[1] if secret.startswith("whsec_") else secret
    try:
        key = base64.b64decode(key_part, validate=True)
    except (binascii.Error, ValueError):
        return None
    return key or None


def secret_problem(creds: dict[str, Any], field: str) -> Optional[str]:
    """Why `field` cannot authenticate a webhook, or None when it can.

    THE usability check: the receiver (`_require_secret`) rejects on it and
    `webhook_warnings` reports it, so "set but unusable" is as loud as
    "not set". The returned phrase completes "<FIELD> …" and never contains
    any part of the value.
    """
    secret = configured_secret(creds, field)
    if not secret:
        return "is not set"
    if _FIELD_KINDS.get(field) == "svix" and svix_key(secret) is None:
        return (
            "is set but unusable (expected 'whsec_' followed by a non-empty "
            "base64 signing key, exactly as shown in the vendor dashboard)"
        )
    return None


def credential_errors(vendor_slug: str, creds: dict[str, Any]) -> list[str]:
    """Create-time validation of webhook secrets; [] when acceptable.

    Blank is allowed (poll-only use — the instance is created with a
    warning). A value that IS supplied must be usable, and a shared token
    must meet MIN_TOKEN_LENGTH. Messages never echo the value.
    """
    errors: list[str] = []
    for field, kind in _FIELD_KINDS.items():
        if not field.startswith(vendor_slug.upper() + "_"):
            continue
        secret = configured_secret(creds, field)
        if not secret:
            continue
        problem = secret_problem(creds, field)
        if problem:
            errors.append(f"{field_label(field)} {problem}")
        elif kind == "token" and len(secret) < MIN_TOKEN_LENGTH:
            errors.append(
                f"{field_label(field)} is too short ({len(secret)} "
                f"characters): use at least {MIN_TOKEN_LENGTH} random "
                "characters, or leave it blank and let Athena generate one. "
                "This token is the only thing authenticating a public endpoint."
            )
    return errors


def secret_origin(field: str) -> Optional[SecretOrigin]:
    """'platform' / 'vendor' for a known webhook-secret field, else None."""
    spec = SECRET_SPECS.get(field)
    return spec.origin if spec else None


def webhook_choice_errors(
    vendor_slug: str, creds: dict[str, Any], enable_webhook: Optional[bool]
) -> list[str]:
    """Create-time validation of the operator's webhook CHOICE; [] when fine.

    `enable_webhook` is the explicit answer to "do you want real-time
    webhooks?": None (older callers) keeps the legacy reading — a blank secret
    means poll-only. True/False must agree with what was supplied, because a
    silent reinterpretation here leaves a public route either dead or armed
    against the operator's wishes. Messages never echo a value.
    """
    if enable_webhook is None:
        return []
    field = WEBHOOK_SECRET_FIELDS.get(vendor_slug)
    if field is None:
        if enable_webhook:
            return [f"{vendor_slug} has no inbound webhook to enable"]
        return []
    supplied = bool(configured_secret(creds, field))
    if not enable_webhook:
        if supplied:
            return [
                f"enable_webhook is false but {field} was supplied — drop the "
                "value for poll-only use, or enable webhooks"
            ]
        return []
    if not supplied and SECRET_SPECS[field].origin == "vendor":
        return [
            f"{field_label(field)} is issued by the vendor, not by Athena: create "
            "the webhook endpoint on the vendor side and paste the signing "
            "secret it shows you"
        ]
    return []


def should_generate(
    vendor_slug: str, creds: dict[str, Any], enable_webhook: Optional[bool]
) -> Optional[WebhookSecretSpec]:
    """The spec to mint a token for, or None. Only when the operator asked for
    webhooks, left the field blank, and the token is OURS to define."""
    if enable_webhook is not True:
        return None
    field = WEBHOOK_SECRET_FIELDS.get(vendor_slug)
    spec = SECRET_SPECS.get(field) if field else None
    if spec is None or spec.origin != "platform":
        return None
    if configured_secret(creds, spec.field):
        return None
    return spec


def generate_token() -> str:
    """A fresh shared token from the OS CSPRNG. The caller stores it in the
    vault and shows it to the operator exactly once; it must never be logged,
    audited or returned by any read-back surface."""
    return secrets.token_urlsafe(GENERATED_TOKEN_BYTES)


def webhook_choice(record: Any) -> Optional[str]:
    """'on' / 'off' when the operator answered the webhook question at create
    time, None for legacy rows that predate it."""
    config = getattr(record, "instance_config", None)
    value = config.get(WEBHOOK_CHOICE_KEY) if isinstance(config, dict) else None
    return value if value in ("on", "off") else None


def receives_webhooks(record: Any) -> bool:
    """True only when a correctly-sent webhook WOULD be accepted: the vendor
    has a route, the operator did not choose poll-only, AND a usable secret is
    stored. The receiver fails closed without one, so "enabled" alone used to
    let the card say inbound webhooks were "not affected" by a polling failure
    on an instance that rejects every one of them. Opens the vault (once);
    surfaces that also need the warnings should call `webhook_status`."""
    return webhook_status(record).usable


def missing_secret_warning(
    vendor_slug: str, field: str, problem: str = "is not set", vendor_name: str = "",
) -> str:
    """Operator-facing sentence for an instance with no usable webhook secret."""
    return (
        f"{field_label(field)} {problem} — inbound {vendor_name or vendor_slug} "
        f"webhooks are rejected (401) until it is fixed. {replace_hint(vendor_name)}"
    )


def no_ingest_host_warning(vendor_name: str) -> str:
    """Webhooks are armed (a usable secret exists) but nothing can reach them."""
    from apps.octo.instances import public_urls

    return (
        "Real-time webhooks are switched on for this integration, but this "
        f"deployment has no public ingest hostname, so {vendor_name} has "
        "nowhere to send them. Polling is unaffected. "
        f"{public_urls.SET_INGEST_HOST_HOWTO} The webhook token you saved "
        "stays valid; the webhook URL then appears under 'Setup guide' on "
        "this card."
    )


def webhook_notes(record: Any, vendor_name: str = "") -> list[str]:
    """NEUTRAL, informational lines for one instance — a deliberate choice, not
    a fault. Today: the operator picked poll-only at create time. Reads no
    credentials."""
    if WEBHOOK_SECRET_FIELDS.get(getattr(record, "vendor_slug", "")) is None:
        return []
    if webhook_choice(record) == "off":
        name = vendor_name or getattr(record, "vendor_slug", "")
        return [POLL_ONLY_NOTE.format(path=recovery_path(name))]
    return []


@dataclass(frozen=True)
class WebhookStatus:
    """Everything the read-back surfaces say about one instance's inbound
    webhook path, from ONE vault read."""
    # The vendor has a webhook route and the operator did not choose poll-only.
    enabled: bool
    # …and a usable secret is stored: a correctly-sent request would be
    # accepted. False → the receiver rejects every request (it fails closed).
    usable: bool
    warnings: list[str]
    notes: list[str]


def webhook_warnings(record: Any, vendor_name: str = "") -> list[str]:
    """Warnings for one persisted instance; [] when nothing is wrong or the
    vendor has no webhook route. See `webhook_status`."""
    return webhook_status(record, vendor_name).warnings


def webhook_status(record: Any, vendor_name: str = "") -> WebhookStatus:
    """Enabled / usable / warnings / notes for one persisted instance. Never
    returns or logs a credential value.

    An explicit poll-only choice is NOT a warning (see `webhook_notes`): the
    create route refuses a secret alongside it, so there is nothing to check
    and the vault is not opened. Legacy rows (choice unknown) keep the loud
    wording, because a missing secret there may well be an accident."""
    from apps.octo.instances import public_urls

    vendor_slug = getattr(record, "vendor_slug", "")
    field = WEBHOOK_SECRET_FIELDS.get(vendor_slug)
    if field is None:
        return WebhookStatus(False, False, [], [])
    if webhook_choice(record) == "off":
        return WebhookStatus(False, False, [], webhook_notes(record, vendor_name))
    name = vendor_name or vendor_slug
    try:
        creds = credentials.load(record.cred_ref)
    except Exception:
        logger.exception(
            "[webhook-auth] could not read credentials for %s instance",
            vendor_slug,
        )
        return WebhookStatus(True, False, [
            f"Stored credentials for {name} could not be read — "
            f"inbound webhooks are rejected (401) until that is fixed. "
            f"{replace_hint(vendor_name)}"
        ], [])
    problem = secret_problem(creds, field)
    if problem:
        return WebhookStatus(True, False, [
            missing_secret_warning(vendor_slug, field, problem, vendor_name)
        ], [])
    warnings: list[str] = []
    if (
        _FIELD_KINDS.get(field) == "token"
        and len(configured_secret(creds, field)) < MIN_TOKEN_LENGTH
    ):
        # Predates the create-time floor: still honoured, but say so.
        warnings.append(
            f"{field_label(field)} is shorter than {MIN_TOKEN_LENGTH} "
            f"characters — weak for a public endpoint. {replace_hint(vendor_name)}"
        )
    if public_urls.public_ingest_base_url() is None:
        # Armed, but unreachable: say so on the card, not only in the wizard.
        warnings.append(no_ingest_host_warning(name))
    return WebhookStatus(True, True, warnings, [])
