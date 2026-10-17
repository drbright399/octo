"""Pydantic schemas for request/response bodies.

Kept thin: the canonical shapes live in the core modules (registry.Client,
TokenRow, etc.) and we mirror them here for OpenAPI generation.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

from pydantic import AfterValidator, BaseModel, Field


def _audit_reason(value: str) -> str:
    text = " ".join(value.split())
    if len(text) < 3:
        raise ValueError("a reason of at least 3 characters is required")
    return text


# The reason an audited change carries, as it is recorded: whitespace
# collapsed, 3..500 characters of it — "   " is refused at validation, BEFORE
# anything is audited.
AuditReason = Annotated[str, Field(min_length=3, max_length=500),
                        AfterValidator(_audit_reason)]

Tier = Literal["standard", "premium"]
Status = Literal["active", "disabled", "offboarded", "archived"]
Severity = Literal["low", "medium", "high", "critical"]
EventSeverity = Literal["info", "low", "medium", "high", "critical"]
IocType = Literal["ip", "ipv6", "domain", "url", "md5", "sha1", "sha256",
                   "email", "cidr", "cve", "other"]
ComplianceFlag = Literal["CJIS", "HIPAA", "GLBA", "PCI", "FERPA", "SOX",
                          "ATTORNEY_CLIENT", "PUBLIC_RECORDS", "NONE"]
TokenKind = Literal["buoy", "service", "admin"]


class ErrorBody(BaseModel):
    code: str = Field(examples=["AUTH_INVALID"])
    message: str
    request_id: str


class ClientOut(BaseModel):
    slug: str
    display_name: str
    tier: Tier
    contact_email: Optional[str] = None
    notification_email: Optional[str] = None
    notification_sla_hours: int = 24
    compliance_flags: list[ComplianceFlag]
    status: Status
    retention_days: int
    onboarded_at: str
    disabled_at: Optional[str] = None
    offboarded_at: Optional[str] = None
    archived_at: Optional[str] = None
    notes: Optional[str] = None
    schema_version: int


class ClientCreate(BaseModel):
    slug: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$",
                       examples=["acme-msp"])
    display_name: str
    tier: Tier = "standard"
    contact_email: Optional[str] = None
    notification_email: Optional[str] = None
    compliance_flags: list[ComplianceFlag] = Field(default_factory=lambda: ["NONE"])
    retention_days: int = Field(default=365, ge=30, le=2555)
    notes: Optional[str] = None
    reason: Optional[str] = None


class ClientUpdate(BaseModel):
    display_name: Optional[str] = None
    tier: Optional[Tier] = None
    contact_email: Optional[str] = None
    notification_email: Optional[str] = None
    compliance_flags: Optional[list[ComplianceFlag]] = None
    retention_days: Optional[int] = Field(default=None, ge=30, le=2555)
    notes: Optional[str] = None
    reason: Optional[str] = None


class ClientRename(BaseModel):
    new_slug: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    reason: str


class ReasonOnly(BaseModel):
    reason: str


class PurgeRequest(BaseModel):
    confirm: bool
    reason: str


class TokenOut(BaseModel):
    id: int
    slug: str
    prefix: str
    kind: TokenKind
    label: str
    created_at: str
    created_by: str
    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None
    last_used_at: Optional[str] = None


class TokenCreate(BaseModel):
    kind: TokenKind
    label: str = Field(min_length=1, max_length=200)
    reason: Optional[str] = None
    # F.4b — service-kind tokens may bind to a registered source_instance.
    # Both fields together (or both None). The core layer rejects half-set.
    source_type: Optional[str] = Field(
        default=None,
        description="When set together with source_instance_id, binds this "
                     "service-kind token to a registered source instance. "
                     "Must match a key in SOURCE_REGISTRY.",
    )
    source_instance_id: Optional[str] = Field(
        default=None,
        description="When set together with source_type, binds this token "
                     "to that specific source instance for the tenant.",
    )


class TokenCreateResult(BaseModel):
    token_id: int
    slug: str
    kind: TokenKind
    label: str
    prefix: str
    source_type: Optional[str] = None
    source_instance_id: Optional[str] = None
    plaintext: str = Field(
        description="Returned exactly once. Store in the recipient's vault now; "
                    "it is not recoverable.",
    )


# F.4b — source-instance admin models

class SourceInstanceCreate(BaseModel):
    source_type: str = Field(
        min_length=1, max_length=64,
        description="Must match a registered source-type plugin (e.g. 'wazuh').",
    )
    source_instance_id: str = Field(
        pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$",
        max_length=128,
        description="Slug-shaped identifier unique within (slug, source_type). "
                     "Examples: 'primary', 'msp-a-region2'.",
    )
    display_name: str = Field(min_length=1, max_length=200)
    description: Optional[str] = None
    reason: Optional[str] = None


class SourceInstanceOut(BaseModel):
    slug: str
    source_type: str
    source_instance_id: str
    display_name: str
    description: Optional[str] = None
    created_at: str
    created_by_operator: Optional[int] = None
    revoked_at: Optional[str] = None
    revoked_by_operator: Optional[int] = None
    revoked_reason: Optional[str] = None
    is_active: bool


class IndicatorOut(BaseModel):
    id: int
    value: str
    type: IocType
    source: str
    severity: Severity
    confidence: float
    context: Optional[str] = None
    first_seen: str
    last_seen: str
    hits: int
    deleted_at: Optional[str] = None
    promoted_at: Optional[str] = None


class IndicatorCreate(BaseModel):
    value: str
    type: IocType
    source: str
    severity: Severity = "medium"
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    context: Optional[dict[str, Any]] = None
    reason: Optional[str] = None


class IndicatorIngest(BaseModel):
    value: str
    type: IocType
    source: Optional[str] = None
    severity: Severity = "medium"
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    context: Optional[dict[str, Any]] = None


class EventIngest(BaseModel):
    event_type: str
    severity: EventSeverity = "info"
    source_host: Optional[str] = None
    # Open shape — the guard runs before this lands anywhere
    data: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    id: int
    received_at: str
    source: str
    source_host: Optional[str] = None
    event_type: str
    severity: EventSeverity
    payload: str
    payload_sha256: str
    relay_status: str
    relay_attempts: int
    relayed_at: Optional[str] = None


class AuditOut(BaseModel):
    id: int
    ts: str
    actor: str
    actor_kind: str
    action: str
    target_kind: str
    target_id: Optional[str] = None
    before_state: Optional[str] = None
    after_state: Optional[str] = None
    reason: Optional[str] = None
    request_id: str
    client_slug: str
    prev_hash: str
    row_hash: str


class AuditVerifyResult(BaseModel):
    scope: str
    ok: bool
    rows: int
    first_error: Optional[str] = None


class PatternOut(BaseModel):
    id: int
    ioc_type: IocType
    ioc_value: str
    first_seen: str
    last_seen: str
    tlp: str
    client_count: int
    severity_max: Severity
    confidence_avg: float
    pepper_version: str
    promoted_at: str


class IngestResult(BaseModel):
    ok: bool
    slug: str
    event_id: Optional[int] = None
    # Migration 036 tiering: 'signal' → `event_id` (events.db);
    # 'telemetry' → `telemetry_id` (telemetry.db).
    tier: Optional[str] = None
    telemetry_id: Optional[int] = None
    indicator_id: Optional[int] = None
    guard_hits: int = 0
    incident_id: Optional[int] = None
    reason: Optional[str] = None


# F.4b — source-ingestion request/response shapes.
#
# The request body is intentionally permissive: the source adapter does the
# strict per-source validation in `validate()`, so this Pydantic model only
# enforces "it parses as a JSON object." This keeps OCTO from being the
# bottleneck on schema evolution — when a new Wazuh / Splunk / etc. version
# adds a field, the adapter handles it; this Pydantic model never has to
# change.
class SourceAlertIngest(BaseModel):
    payload: dict[str, Any] = Field(
        description="Source-native alert envelope. Validated by the registered "
                     "SourceAdapter for the URL's source_type.",
    )


class SourceIngestResult(BaseModel):
    ok: bool
    slug: str
    source_type: str
    source_instance_id: str
    event_id: Optional[int] = None
    idempotent: bool = Field(
        default=False,
        description="True if this alert was already ingested earlier (per "
                     "the adapter's idempotency_key) and we returned the "
                     "existing event without re-inserting.",
    )
    summary: Optional[str] = Field(
        default=None,
        description="Operator-readable one-liner produced by "
                     "adapter.human_summary(). Mirrors what's stored in "
                     "events.db.summary so callers don't need a follow-up GET.",
    )
    indicators_extracted: int = 0
    guard_hits: int = 0
    reason: Optional[str] = None


class WebhookReceiptOut(BaseModel):
    """Inbound-webhook reachability for one adapter instance — on both the
    instance list and the Integrations aggregator. Adapter-agnostic. Carries
    timestamps, counters, a reason CLASS and platform-authored sentences:
    never request content, an address or a credential.

    Built by `webhook_receipt_out` from `instances.webhook_receipt`."""
    # The vendor has a webhook route and the operator did not choose
    # poll-only. False → the console shows nothing about webhooks here.
    enabled: bool = False
    # …and a usable secret is stored, so a correctly-sent request WOULD be
    # accepted. False → every request is rejected (see the card's warning).
    usable: bool = False
    # PERSISTED (survive a restart) — this is what makes "never" truthful.
    last_accepted_at: Optional[str] = None
    last_rejected_at: Optional[str] = None
    last_reject_reason: Optional[str] = None
    # Has ANY request, accepted or rejected, ever reached this instance's URL?
    ever_reached: bool = False
    # IN MEMORY — since `counting_since` (the service's last start).
    accepted_since_start: int = 0
    rejected_since_start: int = 0
    counting_since: Optional[str] = None
    # Rolling window: the last hour, or since start when that is shorter.
    rejected_recent: int = 0
    rejected_recent_by_reason: dict[str, int] = Field(default_factory=dict)
    recent_window: Literal["hour", "since_start"] = "since_start"
    # Platform-authored lines the console renders as-is.
    recent_rejections: list[str] = Field(default_factory=list)
    last_reject_detail: Optional[str] = None
    # The calm edge checklist; only while nothing has ever arrived.
    guidance: list[str] = Field(default_factory=list)


def webhook_receipt_out(rec: Any, status: Any) -> WebhookReceiptOut:
    """`status` is the instance's `webhook_auth.WebhookStatus`. A poll-only or
    webhook-less instance gets the all-default (disabled) shape and the
    receipt store is not consulted."""
    from apps.octo.instances import webhook_receipt

    if not status.enabled:
        return WebhookReceiptOut()
    snap = webhook_receipt.snapshot(rec.id, rec.vendor_slug)
    return WebhookReceiptOut(
        enabled=True,
        usable=status.usable,
        **snap,
        **webhook_receipt.describe(snap, rec.vendor_slug, usable=status.usable),
    )
