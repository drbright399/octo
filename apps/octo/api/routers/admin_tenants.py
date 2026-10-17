"""Tenant manager — `/api/v1/admin/tenants` and `/api/v1/admin/quarantine`.

The lifecycle surface for the `clients` table now that integrations create
tenants by themselves (migration 033, `instances.tenant_autocreate`):

  GET   /admin/tenants                    every tenant with origin / kind /
                                          review_state / compliance tags /
                                          AI policy / mapped vendor sites /
                                          event count / pending request /
                                          possible-duplicate hints (a chip
                                          for a human — never a merge) /
                                          placeholder flags (auto-created,
                                          name or slug still "<vendor>
                                          site …": no client user may be
                                          scoped to it — admin_ops)
  GET   /admin/tenants/review-summary     the counts behind the dashboard's
                                          "needs review" notice (awaiting a
                                          tag, quarantined, pending requests,
                                          cloud-AI sign-offs expiring /
                                          expired) — cheap (registry +
                                          quarantine COUNTs, no per-tenant
                                          store reads), unaudited
  POST  /admin/tenants                    create (admin_clients semantics +
                                          kind / compliance) — audited
  PATCH /admin/tenants/{slug}             display_name, kind, compliance_flags,
                                          ai_policy ('cloud' = super_admin),
                                          review_state → confirmed — audited
                                          with before/after. A change after
                                          which the tenant RUNS as cloud AI
                                          (e.g. tagging a 'cloud' tenant
                                          'none') takes the sign-off's own
                                          bar: super_admin + step-up. A confirmed
                                          tenant never goes back to kind
                                          'unclassified' (422)
  POST  /admin/tenants/bulk-update        the review at scale: ≤ 200
                                          {slug, patch} items under PATCH's
                                          own rules, all-or-nothing —
                                          `dry_run` answers the per-row diff;
                                          applying writes nothing unless
                                          EVERY row is valid (per-row errors
                                          returned), then one transaction and
                                          one 'tenant_update' audit row per
                                          changed tenant
  POST  /admin/tenants/{slug}/offboard    status offboarded; mappings FROZEN
                                          (kept, pointing at the offboarded
                                          slug, so the site's traffic
                                          quarantines as 'offboarded-tenant'
                                          instead of auto-creating a
                                          look-alike); client tokens revoked;
                                          sessions of client users scoped to
                                          it ended; instance defaults
                                          pointing at it cleared; data KEPT.
                                          TWO-PERSON by default (see below)
  POST  /admin/tenants/{slug}/merge-into/{target}
                                          events copied, mappings re-pointed,
                                          subject archived (its sign-offs
                                          revoked); unions the subject's
                                          compliance regimes onto the target
                                          (an untagged subject takes a 'none'
                                          target back to []) and revokes the
                                          target's cloud-AI sign-off when its
                                          tags change. A failure after the
                                          copy removes the copied events
                                          again. TWO-PERSON by default
  GET   /admin/tenants/{slug}/merge-into/{target}/preview
                                          admin+, unaudited: what the merge
                                          would do and leave behind, its
                                          caveats, and whether the
                                          single-person exception applies
  GET   /admin/tenants/requests           the queue (?state, ?approval_mode)
  POST  /admin/tenants/requests/{id}/approve | reject | cancel
                                          approve/reject: super_admin, and
                                          NOT the requester; approving
                                          APPLIES the change (pre-checked
                                          before any audit row; a failed
                                          apply is audited as such). cancel:
                                          the requester
  POST  /admin/tenants/requests/{id}/post-review
                                          admin+ OTHER than the one who applied
                                          a single-person change: reviewed_ok
                                          | reviewed_concern, with a note

Offboard and merge (v0.10 item 7). `approval_mode` in the body:
  'two_person' (the DEFAULT, for everyone): a change request that a
      super_admin OTHER than the requester approves — answered 202. The
      only path an admin has.
  'single_attested': a super_admin applies it alone, as an explicit
      ATTESTED EXCEPTION. Refused, each with its own error and nothing
      written, unless ALL of: the caller is super_admin (403); a typed
      `attestation` of ≥ 40 characters (422 ATTESTATION_REQUIRED);
      `confirm_subject` equal to the subject slug, checked HERE, not only in
      the browser (422 SUBJECT_CONFIRMATION_MISMATCH); for a merge, the
      eligibility guards (409 SINGLE_PERSON_INELIGIBLE, whose message says
      what would make the pair eligible, and offers the two-person request —
      or says nobody could approve one): the target's EFFECTIVE AI policy is
      not more permissive than the subject's (none < local < cloud), the
      subject carries no compliance regime the target lacks, and the subject
      is active (an offboarded one's frozen mappings stay frozen); and an active
      step-up window (`require_step_up`, 401 STEP_UP_REQUIRED) — asked for
      last, so nobody re-authenticates only to be refused. Applied, it
      leaves a change record (state 'applied', approval_mode
      'single_attested', the attestation verbatim, the typed slug,
      post_review_state 'pending'), the ordinary 'tenant_merge' /
      'tenant_offboard' audit row with after_state.approval_mode =
      'single_attested', a distinct 'tenant_merge_single_attested' /
      'tenant_offboard_single_attested' marker row (the attestation's
      sha256, never its text), and a notice to every OTHER admin+
      (`auth.operator_notices`: in-app now, e-mail after commit when a
      Resend integration is configured — never fatal, always recorded).
  No environment variable or setting turns either rule off.
Offboard takes the same exception (no eligibility guards — no data moves
between tenants) rather than becoming request-only: it is how a departed
client's access is cut off NOW, and a bundle with a single super_admin must
still be able to do that.
  GET   /admin/quarantine                 held events (paged; filter by
                                          instance / reason / vendor tenant)
  GET   /admin/quarantine/{id}            one held event, payload as text
  POST  /admin/quarantine/{id}/route      ingest it into a tenant (existing
                                          or new) through the adapter's own
                                          extract path, map the vendor site
                                          so its future traffic routes. The
                                          payload is checked as replayable
                                          BEFORE a new tenant is created
  POST  /admin/quarantine/{id}/discard
  POST  /admin/quarantine/bulk-route      every held event from one vendor
                                          site at once (optionally one hold
                                          reason — the console's group);
                                          truncated payloads are SKIPPED and
                                          counted, never fatal, and the site
                                          is mapped as long as one replayed
  POST  /admin/quarantine/bulk-discard    the same unit, discarded with a
                                          reason

Every route is admin+ (super_admin where stated). Viewers are CLIENT users
and never reach any of this — a scoped viewer sees only its own tenant's
events through the dashboard/search routes, which do not read this table's
lifecycle columns, the request queue or the quarantine store at all — and
those routes drop a scoped slug the moment its tenant stops being active.

Every mutation is written to the hash-chained global audit log
(`auth.audit`), actor = the operator; the integration is the actor for what
it did on its own (see `tenant_autocreate`). Reads are not audited (a list
is not a decision) — except GET /admin/quarantine/{id}, which hands out a
raw held payload and is one `quarantine_fetch` row per call
(docs/audit-policy.md).

`admin_clients.py` (the operators-page scope picker) keeps working; its
POST creates through the same audited path as POST /admin/tenants.

AI policy (v0.10): every tenant payload here — list, create, PATCH, bulk
rows — carries the EFFECTIVE policy next to the stored one
(`instances.ai_policy`): 'cloud' without a live compliance sign-off runs as
'local', and the payload says why. A compliance-flag change revokes the
tenant's sign-off inside the same transaction, recorded in its audit row.
Two ways lead to cloud — a live sign-off, or the tag ["none"] on a tenant
asking for cloud — and both take the same bar: super_admin + step-up
(`_cloud_clearance`; an admin who can neither set 'cloud' nor sign cannot
open the gate by re-tagging). Offboarding or merging a tenant away revokes
its own sign-offs; it runs as 'none' from then on. The sign-off routes
themselves live in `tenant_compliance.py`.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import timedelta
from typing import Any, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from apps.octo import client_provisioning, paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import (
    ROLE_TIER,
    operator_max_tier,
    session_admin_plus,
    session_super_admin,
)
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import audit, operator_notices, sessions
from apps.octo.db import connect, transaction
from apps.octo.ingest import SqliteIngestSink, arrival
from apps.octo.ingest.presentation import clean_line
from apps.octo.ingest.timestamps import format_utc_ms, utcnow_iso
from apps.octo.instances import ai_policy, quarantine, tenant_autocreate, tenant_map
from apps.octo.instances.manager import get_instance, list_instances
from apps.octo.instances.tenant_lifecycle import (
    AI_POLICIES,
    COMPLIANCE_TAGS,
    KINDS,
    MAX_DISPLAY_NAME,
    compliance_flags_json,
    duplicate_hints,
    parse_compliance_flags,
    validate_compliance_flags,
)
from apps.octo.instances.vendor_tenants import MAX_LABEL_CHARS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/tenants", tags=["admin-tenants"])
quarantine_router = APIRouter(prefix="/admin/quarantine", tags=["admin-quarantine"])

# A merge copies the subject's events into the target one by one (idempotent
# on the sink's identity). Beyond this it is a maintenance job, not a click.
MERGE_MAX_EVENTS = 50_000
_MERGE_BATCH = 500
MAX_REASON = 500
MAX_NOTE = 500
QUARANTINE_PAGE_MAX = 200
BULK_ROUTE_MAX = 500
# One bulk review is at most this many tenants — a screenful of decisions,
# small enough to validate and write in one registry transaction.
BULK_UPDATE_MAX = 200
# The attested single-person merge / offboard (v0.10 item 7).
APPROVAL_MODES: tuple[str, ...] = ("two_person", "single_attested")
ATTESTATION_MIN_CHARS = 40
ATTESTATION_MAX_CHARS = 2000
POST_REVIEW_VERDICTS: dict[str, str] = {"ok": "reviewed_ok", "concern": "reviewed_concern"}
ATTESTED_LIST_MAX = 100
# The dashboard warns this long before a live cloud-AI sign-off lapses (a
# batch signed together lapses together — the tenant then runs as local).
SIGNOFF_EXPIRY_WARN_DAYS = 30

# What a merge does NOT do, and what it costs — shown by the merge dialog
# before anyone confirms (GET …/merge-into/{target}/preview). Each line is
# what the code below does; change them together.
MERGE_CAVEATS: tuple[tuple[str, str], ...] = (
    ("irreversible",
     "Irreversible: the source tenant is archived and nothing in Athena brings an "
     "archived tenant back."),
    ("events_only",
     "Only events are copied. Incidents, agent notes, indicators, tickets, DNS / "
     "network telemetry and the tenant's own audit log stay in the archived "
     "source's stores; its buoys stay registered to it, with their tokens revoked."),
    ("retriage",
     "Copied events are new rows in the target: the triage worker (when enabled) "
     "annotates those at or above its severity floor on its next pass, under the "
     "TARGET's AI policy — the source's own triage notes are not copied."),
    ("write_lock",
     f"The registry write lock is held for the whole copy (up to {MERGE_MAX_EVENTS:,} events): "
     "every registry write — sign-ins, step-up, webhook receipts, tenant auto-creation, "
     "other admin changes — waits, and one that waits past SQLite's busy timeout "
     "(5 seconds by default) fails. Merge in a quiet window."),
    ("scoped_users",
     "Client users scoped to the source are signed out, and are not re-scoped to the "
     "target — re-scope them under Operators. Staff with all-tenant scope are not "
     "affected."),
)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class MappedSourceOut(BaseModel):
    vendor: str
    instance_id: int
    vendor_tenant_id: str
    label: str | None = None
    match_source: str


class CreatedByInstanceOut(BaseModel):
    instance_id: int
    vendor: str
    label: str


class ChangeRequestOut(BaseModel):
    id: int
    kind: str
    subject_slug: str
    target_slug: str | None = None
    requested_by: int
    requested_at: str
    reason: str
    state: str
    decided_by: int | None = None
    decided_at: str | None = None
    decision_note: str | None = None
    # v0.10: 'two_person' (a request a second super_admin decided) or
    # 'single_attested' (applied alone by `requested_by`, on the typed
    # attestation below, with the subject slug as they typed it).
    approval_mode: str = "two_person"
    attestation: str | None = None
    subject_confirmation: str | None = None
    # A single-person change waits for an optional review by a SECOND
    # admin+: not_requested | pending | reviewed_ok | reviewed_concern.
    post_review_state: str = "not_requested"
    post_reviewed_by: int | None = None
    post_reviewed_at: str | None = None
    post_review_note: str | None = None


class DuplicateHintOut(BaseModel):
    """Another tenant whose name looks like the same business
    (`tenant_lifecycle.duplicate_rule`). A hint — the merge stays a human's
    decision, through the ordinary merge flow."""
    slug: str
    display_name: str
    status: str
    rule: str                        # 'same-name' | 'name-prefix'


class SignoffStatusOut(BaseModel):
    """Where a tenant stands for cloud AI (`instances.ai_policy`):
    not_required (tagged 'none') | required (never signed) | live | expired |
    revoked | flags_changed (its flags moved since the sign-off)."""
    state: str
    signoff_id: int | None = None
    signed_by: int | None = None
    signed_at: str | None = None
    expires_at: str | None = None
    flags_covered: list[str] | None = None


class TenantOut(BaseModel):
    slug: str
    display_name: str
    status: str
    origin: str
    kind: str
    review_state: str
    compliance_flags: list[str] = Field(default_factory=list)
    # The STORED intent ('cloud' may be set without a sign-off) …
    ai_policy: str
    # … and what actually runs: 'cloud' without a live sign-off runs as
    # 'local'. `ai_policy_reason` says why, in one sentence.
    effective_ai_policy: str = "none"
    ai_policy_reason: str | None = None
    signoff: SignoffStatusOut = Field(default_factory=lambda: SignoffStatusOut(state="required"))
    created_by_instance: CreatedByInstanceOut | None = None
    onboarded_at: str
    offboarded_at: str | None = None
    archived_at: str | None = None
    notes: str | None = None
    event_count: int = 0
    last_event_at: str | None = None
    mapped_sources: list[MappedSourceOut] = Field(default_factory=list)
    pending_request: ChangeRequestOut | None = None
    duplicate_hints: list[DuplicateHintOut] = Field(default_factory=list)
    # Auto-created and still carrying the vendor-named placeholder: its name
    # ("<vendor> site …" — rename it) and/or its slug ("<vendor>-site-…",
    # which never changes — merge it into a properly named tenant). No
    # viewer (client user) may be scoped to it while either stands.
    placeholder_name: bool = False
    placeholder_slug: bool = False


class TenantListResponse(BaseModel):
    tenants: list[TenantOut]
    pending_review: int
    quarantined: int
    kinds: list[str] = Field(default_factory=lambda: list(KINDS))
    compliance_tags: list[str] = Field(default_factory=lambda: list(COMPLIANCE_TAGS))
    ai_policies: list[str] = Field(default_factory=lambda: list(AI_POLICIES))


class ReviewSummaryOut(BaseModel):
    """What needs a human right now — active tenants awaiting their tag,
    events held in quarantine, change requests awaiting a second person,
    and cloud-AI sign-offs about to lapse (or lapsed: the tenant runs as
    local until someone signs again)."""
    pending_review: int
    quarantined: int
    pending_requests: int
    signoffs_expiring: int = 0       # live, expiring within SIGNOFF_EXPIRY_WARN_DAYS
    signoffs_expired: int = 0        # asks for cloud, latest sign-off lapsed by expiry


class CreateTenantRequest(BaseModel):
    slug: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=MAX_DISPLAY_NAME)
    kind: str = "unclassified"
    compliance_flags: list[str] = Field(default_factory=list, max_length=len(COMPLIANCE_TAGS))
    ai_policy: str = "none"


class PatchTenantRequest(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=MAX_DISPLAY_NAME)
    kind: str | None = None
    compliance_flags: list[str] | None = Field(default=None, max_length=len(COMPLIANCE_TAGS))
    ai_policy: str | None = None
    review_state: str | None = None


class BulkUpdateItem(BaseModel):
    slug: str = Field(min_length=1, max_length=64)
    patch: PatchTenantRequest


class BulkUpdateRequest(BaseModel):
    items: list[BulkUpdateItem] = Field(min_length=1, max_length=BULK_UPDATE_MAX)
    # True: validate and answer the per-row diff, write nothing (unaudited —
    # a preview is not a decision).
    dry_run: bool = False


class FieldChangeOut(BaseModel):
    field: str
    before: str | list[str]
    after: str | list[str]


class RowErrorOut(BaseModel):
    code: str
    message: str


class BulkRowOut(BaseModel):
    slug: str
    display_name: str | None = None
    status: str | None = None
    # Empty with no error = the tenant already says all that (nothing written).
    changes: list[FieldChangeOut] = Field(default_factory=list)
    error: RowErrorOut | None = None
    # The AI policy the tenant will RUN with once the row applies (the
    # preview) / now runs with (applied) — 'cloud' on a flagged tenant with
    # no live sign-off runs as 'local' — and its sign-off standing then.
    effective_ai_policy: str | None = None
    signoff: SignoffStatusOut | None = None
    # One line when the row touches AI: "will run as local until signed …",
    # "sign-off #3 will be revoked: compliance flags change".
    ai_policy_note: str | None = None
    # Sign-offs this row's flag change revokes (preview: would revoke).
    signoffs_invalidated: list[int] = Field(default_factory=list)
    # The row makes the tenant run as cloud AI when it did not (or on the
    # 'none' tag where a sign-off stood): the sign-off's bar — super_admin +
    # step-up (`_cloud_clearance`). An admin's row is refused instead.
    step_up_required: bool = False


class BulkUpdateResponse(BaseModel):
    dry_run: bool
    applied: bool
    # The batch's request_id — every per-tenant audit row carries it.
    request_id: str | None = None
    rows: list[BulkRowOut]
    changed: int
    unchanged: int
    errors: int
    # Set when the batch is (or, on a dry run, would be) refused as a whole.
    refusal: RowErrorOut | None = None
    # Applying needs an active step-up window (a row sets step_up_required).
    step_up_required: bool = False


class ReasonRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=MAX_REASON)


class LifecycleActionRequest(ReasonRequest):
    """Offboard / merge. `approval_mode` 'two_person' (default) files a
    request; 'single_attested' is the super_admin's attested exception and
    needs the two fields below — checked by the route, each refusal naming
    the missing piece (no min_length here: a Pydantic 422 would not say
    which rule)."""
    approval_mode: Literal["two_person", "single_attested"] = "two_person"
    # Typed by the operator, stored verbatim on the change record.
    attestation: str | None = Field(default=None, max_length=ATTESTATION_MAX_CHARS)
    # The subject slug as the operator typed it — must equal it exactly.
    confirm_subject: str | None = Field(default=None, max_length=64)


class DecisionRequest(BaseModel):
    note: str | None = Field(default=None, max_length=MAX_NOTE)


class PostReviewRequest(BaseModel):
    verdict: Literal["ok", "concern"]
    note: str = Field(min_length=3, max_length=MAX_NOTE)


class NotificationOut(BaseModel):
    """Who was told of a single-person change (`auth.operator_notices`)."""
    # Other admin+ operators given an in-app notice.
    recipients: int = 0
    # The failure CLASS when the in-app notices could not be created (the
    # change stood; the audit marker records it). None = created.
    in_app_error: str | None = None
    # 'queued' — the e-mail copy goes out after this response, through a
    # configured Resend integration (recorded per recipient; 'not
    # configured' when there is none); 'none' — nobody to e-mail.
    email: str = "none"


class EligibilityReasonOut(BaseModel):
    # 'target_ai_more_permissive' | 'subject_flags_not_on_target' |
    # 'subject_not_active'
    code: str
    message: str
    # What would make the single-person path apply, when something would.
    remedy: str | None = None


class SinglePersonEligibilityOut(BaseModel):
    """May a super_admin merge these two ALONE (attested exception)? The
    owner's guards, on EFFECTIVE AI policies (`instances.ai_policy`)."""
    eligible: bool
    reasons: list[EligibilityReasonOut] = Field(default_factory=list)
    subject_effective_ai_policy: str
    target_effective_ai_policy: str
    subject_flags_not_on_target: list[str] = Field(default_factory=list)
    # Active super_admins OTHER than the caller — who could approve the
    # two-person request. 0: nobody can, and the refusal says so.
    other_super_admins: int = 0


class CaveatOut(BaseModel):
    code: str
    text: str


class MergePreviewOut(BaseModel):
    slug: str
    target: str
    subject_status: str
    events_to_copy: int
    # Stays with the archived subject: counts from its own stores.
    left_behind: dict[str, int] = Field(default_factory=dict)
    mappings_to_repoint: int = 0
    tokens_to_revoke: int = 0
    # Client users scoped to the subject — signed out, not re-scoped.
    scoped_operators: int = 0
    target_flags_added: list[str] = Field(default_factory=list)
    # The target's compliance flags once merged (`ai_policy.merged_flags`) —
    # differs from today's when regimes are added, or when an untagged
    # subject takes a 'none' target back to [] (cloud then needs a sign-off).
    target_flags_after: list[str] = Field(default_factory=list)
    target_signoffs_to_revoke: list[int] = Field(default_factory=list)
    # The subject's own unrevoked sign-offs: revoked — it is archived.
    subject_signoffs_to_revoke: list[int] = Field(default_factory=list)
    single_person: SinglePersonEligibilityOut
    # True for a super_admin: the attested exception is theirs to use (when
    # eligible). An admin only ever files a request.
    caller_may_apply_alone: bool = False
    caveats: list[CaveatOut] = Field(default_factory=list)
    attestation_min_chars: int = ATTESTATION_MIN_CHARS
    attestation_max_chars: int = ATTESTATION_MAX_CHARS


class AccessSeveredOut(BaseModel):
    """What stopped working for the tenant's own users when it left."""
    tokens_revoked: int = 0          # buoy / API bearer tokens
    sessions_revoked: int = 0        # live console sessions of client users scoped to it
    scoped_operators: int = 0        # client user accounts still scoped to it (remove under Operators)
    instance_defaults_cleared: int = 0


class OffboardResponse(BaseModel):
    slug: str
    applied: bool
    status: str
    request: ChangeRequestOut | None = None
    # Kept, not deleted: the site stays known as this tenant's, so its
    # traffic holds as 'offboarded-tenant' rather than creating a look-alike.
    mappings_frozen: int = 0
    access: AccessSeveredOut = Field(default_factory=AccessSeveredOut)
    # The tenant's unrevoked cloud-AI sign-offs, revoked: it has left.
    signoffs_revoked: list[int] = Field(default_factory=list)
    # v0.10: how it was approved. Applied alone: the change record's id, its
    # post-review state, and who was told.
    approval_mode: str = "two_person"
    change_request_id: int | None = None
    post_review_state: str | None = None
    notifications: NotificationOut | None = None


class MergeResponse(BaseModel):
    slug: str
    target: str
    applied: bool
    status: str
    request: ChangeRequestOut | None = None
    mappings_repointed: int = 0
    events_copied: int = 0
    events_skipped: int = 0
    access: AccessSeveredOut = Field(default_factory=AccessSeveredOut)
    # Compliance regimes the subject carried that the target lacked: unioned
    # onto the target, whose sign-off(s) the merge then revoked (the
    # target's cloud AI waits for a new sign-off covering them).
    target_flags_added: list[str] = Field(default_factory=list)
    target_flags_after: list[str] = Field(default_factory=list)
    signoffs_invalidated: list[int] = Field(default_factory=list)
    # The archived subject's own sign-offs, revoked.
    subject_signoffs_revoked: list[int] = Field(default_factory=list)
    approval_mode: str = "two_person"
    change_request_id: int | None = None
    post_review_state: str | None = None
    notifications: NotificationOut | None = None


class RequestListResponse(BaseModel):
    requests: list[ChangeRequestOut]


class QuarantineRowOut(BaseModel):
    id: int
    received_at: str
    instance_id: int
    vendor: str
    source: str
    vendor_tenant_id: str | None = None
    vendor_tenant_label: str | None = None
    reason: str
    event_summary: str | None = None
    payload_sha256: str
    payload_truncated: bool = False
    state: str
    routed_to_slug: str | None = None
    routed_at: str | None = None
    discarded_at: str | None = None
    discard_reason: str | None = None
    # A HELD row whose site name is the same name as exactly one active
    # client ('name-match-suggested' / 'name-already-mapped'): that client,
    # offered as a one-click "map to <client>" (the same-name rule — a
    # name is a suggestion for a human, never a link). Computed at read
    # time from the current tenant list; None otherwise.
    suggested_slug: str | None = None
    suggested_name: str | None = None


class QuarantineListResponse(BaseModel):
    rows: list[QuarantineRowOut]
    total: int
    limit: int
    offset: int
    reasons: list[str] = Field(default_factory=lambda: list(quarantine.REASONS))


class QuarantineDetailOut(QuarantineRowOut):
    # The held payload, as opaque text. Render as text — never as markup.
    payload: str


class NewTenantSpec(BaseModel):
    display_name: str = Field(min_length=1, max_length=MAX_DISPLAY_NAME)
    kind: str = "client"
    compliance_flags: list[str] = Field(default_factory=list, max_length=len(COMPLIANCE_TAGS))


class RouteRequest(BaseModel):
    slug: str | None = None
    new: NewTenantSpec | None = None


class BulkRouteRequest(RouteRequest):
    instance_id: int
    vendor_tenant_id: str = Field(min_length=1, max_length=256)
    # Narrow the unit to one hold reason (the console groups held events by
    # site AND reason); None = every held event from that site.
    quarantine_reason: str | None = Field(default=None, max_length=quarantine.MAX_REASON_CHARS)


class RouteResponse(BaseModel):
    slug: str
    created_tenant: bool = False
    routed: int
    duplicates: int = 0
    # Held rows in the unit whose payload was truncated on arrival: left held
    # (discard them), never a reason to abort the rest.
    skipped: int = 0
    mapping_written: bool = False


class DiscardResponse(BaseModel):
    id: int
    discarded: bool


class BulkDiscardRequest(ReasonRequest):
    instance_id: int
    vendor_tenant_id: str = Field(min_length=1, max_length=256)
    quarantine_reason: str | None = Field(default=None, max_length=quarantine.MAX_REASON_CHARS)


class BulkDiscardResponse(BaseModel):
    discarded: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _audit_row(
    *, operator_id: int, action: str, slug: str, before: Any = None,
    after: Any = None, reason: str | None = None, request_id: str | None = None,
    target_kind: str = "client", target_id: str | None = None,
) -> None:
    """One audited decision. Failure to audit is fatal — callers audit BEFORE
    they change anything, so nothing changes unaudited."""
    g_audit = connect(paths.global_audit_db_path())
    try:
        audit.append(g_audit, audit.AuditEntry(
            actor=str(operator_id),
            actor_kind="human",
            action=action,
            target_kind=target_kind,
            target_id=target_id or slug,
            client_slug=slug,
            before_state=before,
            after_state=after,
            reason=reason,
            request_id=request_id or str(uuid.uuid4()),
        ))
    finally:
        g_audit.close()


def _tenant_row(conn: sqlite3.Connection, slug: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM clients WHERE slug = ?", (slug,)).fetchone()


def _require_tenant(conn: sqlite3.Connection, slug: str) -> sqlite3.Row:
    if not paths.SLUG_RE.match(slug or ""):
        raise APIError("VALIDATION_FAILED", "not a tenant slug")
    row = _tenant_row(conn, slug)
    if row is None:
        raise APIError("CLIENT_NOT_FOUND", f"no tenant {slug!r}")
    return row


def _snapshot(row: sqlite3.Row) -> dict[str, Any]:
    """The audited shape of a tenant row (no free-text notes)."""
    return {
        "slug": row["slug"], "display_name": row["display_name"],
        "status": row["status"], "origin": row["origin"], "kind": row["kind"],
        "review_state": row["review_state"],
        "compliance_flags": parse_compliance_flags(row["compliance_flags"]),
        "ai_policy": row["ai_policy"],
    }


def signoff_status_out(s: ai_policy.SignoffStatus) -> SignoffStatusOut:
    return SignoffStatusOut(
        state=s.state, signoff_id=s.signoff_id, signed_by=s.signed_by,
        signed_at=s.signed_at, expires_at=s.expires_at,
        flags_covered=list(s.flags_covered) if s.flags_covered is not None else None,
    )


def _invalidate_on_flag_change(
    conn: sqlite3.Connection, slug: str, before_raw: Any, after_raw: Any, *,
    operator_id: int, kind: str = "flags_changed", reason: str | None = None,
) -> list[int]:
    """Inside the caller's transaction: when the tenant's canonical flags
    changed, revoke its unrevoked sign-offs (they no longer match anyway —
    this records WHY). Returns the revoked ids for the caller's audit row."""
    before = ai_policy.canonical_flags(before_raw)
    after = ai_policy.canonical_flags(after_raw)
    if before == after:
        return []
    return ai_policy.invalidate_signoffs(
        conn, slug, operator_id=operator_id, kind=kind,
        reason=reason or (
            f"compliance flags changed: {ai_policy.flags_label(before)} → "
            f"{ai_policy.flags_label(after)}"
        ),
    )


def _event_stats(slug: str) -> tuple[int, str | None]:
    """(count, latest received_at) from the tenant's events.db — two indexed
    reads; (0, None) when there is no DB or it is busy."""
    try:
        db_path = paths.client_db_path(slug, "events")
    except Exception:  # noqa: BLE001 — a slug the path layer refuses
        return 0, None
    if not db_path.exists():
        return 0, None
    try:
        conn = connect(db_path, read_only=True)
    except Exception:  # noqa: BLE001
        return 0, None
    try:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        latest = conn.execute(
            "SELECT received_at FROM events ORDER BY received_at DESC LIMIT 1",
        ).fetchone()
        return int(count), (latest[0] if latest else None)
    except sqlite3.OperationalError:
        return 0, None
    finally:
        conn.close()


def _request_out(r: sqlite3.Row) -> ChangeRequestOut:
    return ChangeRequestOut(
        id=int(r["id"]), kind=r["kind"], subject_slug=r["subject_slug"],
        target_slug=r["target_slug"], requested_by=int(r["requested_by"]),
        requested_at=r["requested_at"], reason=r["reason"], state=r["state"],
        decided_by=r["decided_by"], decided_at=r["decided_at"],
        decision_note=r["decision_note"],
        approval_mode=r["approval_mode"], attestation=r["attestation"],
        subject_confirmation=r["subject_confirmation"],
        post_review_state=r["post_review_state"], post_reviewed_by=r["post_reviewed_by"],
        post_reviewed_at=r["post_reviewed_at"], post_review_note=r["post_review_note"],
    )


def _pending_request_for(conn: sqlite3.Connection, slug: str) -> ChangeRequestOut | None:
    r = conn.execute(
        "SELECT * FROM tenant_change_requests WHERE (subject_slug = ? OR target_slug = ?) "
        "AND state = 'pending' ORDER BY id LIMIT 1", (slug, slug),
    ).fetchone()
    return _request_out(r) if r else None


def _instance_index() -> dict[int, Any]:
    return {rec.id: rec for rec in list_instances(include_disabled=True)}


def _tenant_out(
    conn: sqlite3.Connection, row: sqlite3.Row, instances: dict[int, Any],
    hints: list[DuplicateHintOut] | None = None,
    placeholder: frozenset[str] | None = None,
) -> TenantOut:
    """`placeholder`: the row's `tenant_autocreate.placeholder_parts` entry
    (the list looks them up once for every row); None = look it up."""
    slug = row["slug"]
    mappings = conn.execute(
        "SELECT adapter_instance_id, vendor_tenant_id, vendor_tenant_label, match_source "
        "FROM adapter_tenant_map WHERE octo_client_slug = ? ORDER BY adapter_instance_id, "
        "vendor_tenant_id", (slug,),
    ).fetchall()
    created_by = None
    if row["created_by_instance_id"] is not None:
        rec = instances.get(int(row["created_by_instance_id"]))
        created_by = CreatedByInstanceOut(
            instance_id=int(row["created_by_instance_id"]),
            vendor=rec.vendor_slug if rec else "unknown",
            label=rec.display_name if rec else "(removed integration)",
        )
    count, last = _event_stats(slug)
    policy = ai_policy.status_for_row(conn, row)
    if placeholder is None:
        placeholder = tenant_autocreate.placeholder_parts(conn, [slug]).get(slug, frozenset())
    return TenantOut(
        slug=slug,
        display_name=row["display_name"],
        status=row["status"],
        origin=row["origin"],
        kind=row["kind"],
        review_state=row["review_state"],
        compliance_flags=parse_compliance_flags(row["compliance_flags"]),
        ai_policy=row["ai_policy"],
        effective_ai_policy=policy.effective,
        ai_policy_reason=policy.reason,
        signoff=signoff_status_out(policy.signoff),
        created_by_instance=created_by,
        onboarded_at=row["onboarded_at"],
        offboarded_at=row["offboarded_at"],
        archived_at=row["archived_at"],
        notes=row["notes"],
        event_count=count,
        last_event_at=last,
        mapped_sources=[
            MappedSourceOut(
                vendor=(instances[m["adapter_instance_id"]].vendor_slug
                        if m["adapter_instance_id"] in instances else "unknown"),
                instance_id=int(m["adapter_instance_id"]),
                vendor_tenant_id=m["vendor_tenant_id"],
                label=m["vendor_tenant_label"],
                match_source=m["match_source"],
            )
            for m in mappings
        ],
        pending_request=_pending_request_for(conn, slug),
        duplicate_hints=hints or [],
        placeholder_name="name" in placeholder,
        placeholder_slug="slug" in placeholder,
    )


def _duplicate_hints_by_slug(rows: list[sqlite3.Row]) -> dict[str, list[DuplicateHintOut]]:
    """Possible duplicates among the tenants still in play (an archived one
    is history — merged or retired — and never a merge subject or target)."""
    live = {r["slug"]: r for r in rows if r["status"] != "archived"}
    pairs = duplicate_hints((slug, r["display_name"]) for slug, r in live.items())
    return {
        slug: [
            DuplicateHintOut(
                slug=other, display_name=live[other]["display_name"],
                status=live[other]["status"], rule=rule,
            )
            for other, rule in hits
        ]
        for slug, hits in pairs.items()
    }


def _validated_kind(kind: str) -> str:
    if kind not in KINDS:
        raise APIError("VALIDATION_FAILED", f"kind must be one of {', '.join(KINDS)}")
    return kind


def _validated_flags(values: list[str]) -> list[str]:
    try:
        return validate_compliance_flags(values)
    except ValueError as exc:
        raise APIError("VALIDATION_FAILED", str(exc))


def _validated_ai_policy(
    policy: str, caller: sessions.SessionInfo, *, tier: int | None = None,
) -> str:
    """`tier`: the caller's max role tier when the caller already has it (a
    bulk batch looks it up once, not once per row)."""
    if policy not in AI_POLICIES:
        raise APIError("VALIDATION_FAILED", f"ai_policy must be one of {', '.join(AI_POLICIES)}")
    if tier is None and policy == "cloud":
        tier = operator_max_tier(caller.operator_id)
    if policy == "cloud" and (tier or 0) < ROLE_TIER["super_admin"]:
        raise APIError(
            "ISOLATION_VIOLATION",
            "ai_policy 'cloud' (data may leave this deployment) requires super_admin",
        )
    return policy


def _would_row(row: sqlite3.Row, updates: dict[str, Any]) -> dict[str, Any]:
    """The tenant as `updates` would leave it — the columns the AI policy
    reads."""
    return {
        "slug": row["slug"], "status": row["status"],
        "ai_policy": updates.get("ai_policy", row["ai_policy"]),
        "compliance_flags": updates.get("compliance_flags", row["compliance_flags"]),
    }


def _policy_change(
    conn: sqlite3.Connection, row: sqlite3.Row, updates: dict[str, Any],
) -> tuple[ai_policy.AiPolicyStatus, ai_policy.AiPolicyStatus, bool]:
    """(effective policy now, effective policy once `updates` apply, whether
    the canonical flags change) — read on `conn`, nothing written. A flag
    change revokes the sign-offs, so the 'after' answers as if it had."""
    flags_change = "compliance_flags" in updates and (
        ai_policy.canonical_flags(updates["compliance_flags"])
        != ai_policy.canonical_flags(row["compliance_flags"])
    )
    before = ai_policy.status_for_row(conn, row)
    after = ai_policy.status_for_row(
        conn, _would_row(row, updates), assume_flags_changed=flags_change,
    )
    return before, after, flags_change


def _cloud_clearance(
    before: ai_policy.AiPolicyStatus, after: ai_policy.AiPolicyStatus,
) -> str | None:
    """Why a write needs the compliance sign-off's own bar — super_admin +
    step-up — or None.

    A tenant runs as cloud on one of two bases: a live sign-off (recorded
    only by a super_admin under step-up) or the tag ["none"] on a tenant
    that asks for cloud. The second is a PATCH / bulk edit, so it takes the
    same bar as the first; otherwise an admin who can neither set 'cloud'
    nor sign could open the gate by re-tagging a waiting tenant 'none'. The
    bar applies to any write after which the tenant runs as cloud when it
    did not before, and to one that moves a cloud tenant from its sign-off
    onto the 'none' tag (the sign-off is revoked; cloud would stay)."""
    if after.effective != "cloud":
        return None
    if before.effective != "cloud":
        basis = ("with no sign-off (tagged 'none')" if after.signoff.state == "not_required"
                 else f"on sign-off #{after.signoff.signoff_id}")
        return f"this change would make {after.slug} run as cloud AI {basis}"
    if after.signoff.state == "not_required" and before.signoff.state != "not_required":
        return (
            f"this change would keep {after.slug} running as cloud AI on the tag 'none' "
            f"alone, its sign-off #{before.signoff.signoff_id} revoked"
        )
    return None


def _require_cloud_bar(clearance: str, *, tier: int, stepped_up: bool) -> None:
    """The role rule first (an admin is refused, never prompted to
    re-authenticate for something they may not do), then the step-up."""
    if tier < ROLE_TIER["super_admin"]:
        raise APIError(
            "ISOLATION_VIOLATION",
            f"{clearance} — only a super admin may clear a tenant for cloud AI, with step-up "
            "re-authentication (the bar a compliance sign-off has)",
        )
    if not stepped_up:
        raise APIError("STEP_UP_REQUIRED")


# ---------------------------------------------------------------------------
# Tenants — list / create / patch
# ---------------------------------------------------------------------------

@router.get("", response_model=TenantListResponse)
def list_tenants(
    response: Response,
    include_archived: int = Query(default=1),
    _caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantListResponse:
    response.headers["Cache-Control"] = "no-store"
    instances = _instance_index()
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM clients"
        if not include_archived:
            sql += " WHERE status IN ('active','disabled')"
        rows = reg.execute(sql + " ORDER BY review_state DESC, display_name COLLATE NOCASE").fetchall()
        hints = _duplicate_hints_by_slug(rows)
        placeholders = tenant_autocreate.placeholder_parts(reg)
        tenants = [
            _tenant_out(
                reg, r, instances, hints.get(r["slug"]),
                placeholders.get(r["slug"], frozenset()),
            )
            for r in rows
        ]
    finally:
        reg.close()
    return TenantListResponse(
        tenants=tenants,
        pending_review=sum(1 for t in tenants if t.review_state == "pending" and t.status == "active"),
        quarantined=quarantine.held_count(),
    )


def _signoff_expiry_counts(conn: sqlite3.Connection) -> tuple[int, int]:
    """(live sign-offs of active tenants expiring within
    SIGNOFF_EXPIRY_WARN_DAYS, active tenants asking for cloud whose latest
    sign-off lapsed by expiry) — two indexed COUNTs; (0, 0) before 034."""
    now = ai_policy.utcnow()
    now_s = format_utc_ms(now)
    soon_s = format_utc_ms(now + timedelta(days=SIGNOFF_EXPIRY_WARN_DAYS))
    try:
        expiring = conn.execute(
            "SELECT COUNT(*) FROM tenant_compliance_signoffs s JOIN clients c ON c.slug = s.slug "
            "WHERE c.status = 'active' AND s.revoked_at IS NULL "
            "AND s.expires_at > ? AND s.expires_at <= ?", (now_s, soon_s),
        ).fetchone()[0]
        expired = conn.execute(
            "SELECT COUNT(*) FROM clients c JOIN tenant_compliance_signoffs s "
            "ON s.id = (SELECT MAX(id) FROM tenant_compliance_signoffs WHERE slug = c.slug) "
            "WHERE c.status = 'active' AND c.ai_policy = 'cloud' AND s.revoked_at IS NULL "
            "AND s.expires_at <= ?", (now_s,),
        ).fetchone()[0]
    except sqlite3.OperationalError:
        return 0, 0
    return int(expiring), int(expired)


@router.get("/review-summary", response_model=ReviewSummaryOut)
def review_summary(
    response: Response,
    _caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ReviewSummaryOut:
    """The dashboard's "needs review" notice polls this: a few COUNTs, no
    per-tenant store is opened, nothing is audited (a glance is not a
    decision). admin+ only — a viewer is a client user and must not learn
    that other tenants exist."""
    response.headers["Cache-Control"] = "no-store"
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        pending = reg.execute(
            "SELECT COUNT(*) FROM clients WHERE review_state = 'pending' AND status = 'active'",
        ).fetchone()[0]
        requests = reg.execute(
            "SELECT COUNT(*) FROM tenant_change_requests WHERE state = 'pending'",
        ).fetchone()[0]
        expiring, expired = _signoff_expiry_counts(reg)
    finally:
        reg.close()
    return ReviewSummaryOut(
        pending_review=int(pending), quarantined=quarantine.held_count(),
        pending_requests=int(requests), signoffs_expiring=expiring, signoffs_expired=expired,
    )


def create_manual_tenant(
    slug: str, display_name: str, *, kind: str, flags: list[str], ai_policy: str,
    operator_id: int, reason: str, request_id: str | None = None,
) -> str:
    """The ONE way a human creates a tenant (POST /admin/tenants, the
    quarantine route dialog, the legacy POST /admin/clients): validated,
    refused on a taken slug, audited `tenant_create` (origin 'manual') BEFORE
    the row exists, confirmed only when a kind was given — 'unclassified'
    is born pending, whichever door it came through. `kind`, `flags` and
    `ai_policy` are already validated by the caller. Returns the slug."""
    slug = slug.strip()
    display_name = " ".join(display_name.split())
    review_state = "confirmed" if kind != "unclassified" else "pending"
    try:
        client_provisioning.validate_new_client(slug, display_name)
    except client_provisioning.InvalidClientError as exc:
        raise APIError("VALIDATION_FAILED", str(exc))
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        if _tenant_row(reg, slug) is not None:
            raise APIError("CONFLICT", f"client {slug!r} already exists")
    finally:
        reg.close()
    _audit_row(
        operator_id=operator_id, action="tenant_create", slug=slug,
        after={"slug": slug, "display_name": display_name, "origin": "manual",
               "kind": kind, "review_state": review_state,
               "compliance_flags": flags, "ai_policy": ai_policy},
        reason=reason, request_id=request_id or str(uuid.uuid4()),
    )
    try:
        client_provisioning.create_client(
            slug, display_name, origin="manual", kind=kind,
            review_state=review_state, ai_policy=ai_policy,
            compliance_flags_json=compliance_flags_json(flags),
        )
    except client_provisioning.ClientExistsError as exc:
        raise APIError("CONFLICT", str(exc))
    except client_provisioning.InvalidClientError as exc:
        raise APIError("VALIDATION_FAILED", str(exc))
    return slug


@router.post("", response_model=TenantOut, status_code=201)
def create_tenant(
    body: CreateTenantRequest,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantOut:
    kind = _validated_kind(body.kind)
    flags = _validated_flags(body.compliance_flags)
    policy = _validated_ai_policy(body.ai_policy, caller)
    if policy == "cloud" and not ai_policy.signoff_required(flags):
        # Born running as cloud (asks for it, tagged 'none'): the sign-off's
        # bar, as for a PATCH that does the same (`_cloud_clearance`). The
        # role rule was checked above; step-up before anything is written.
        require_step_up(request, caller)
    slug = create_manual_tenant(
        body.slug, body.display_name, kind=kind, flags=flags, ai_policy=policy,
        operator_id=caller.operator_id, reason="tenant created via admin API",
    )
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        return _tenant_out(reg, _require_tenant(reg, slug), _instance_index())
    finally:
        reg.close()


def _patch_updates(
    body: PatchTenantRequest, caller: sessions.SessionInfo, *, tier: int | None = None,
) -> dict[str, Any]:
    """The column → value changes a PATCH asks for, each validated on its own
    (no tenant read yet). PATCH and bulk-update share this."""
    updates: dict[str, Any] = {}
    if body.display_name is not None:
        name = " ".join(body.display_name.split())
        if not name or not name.isprintable():
            raise APIError("VALIDATION_FAILED", "display_name must be printable text")
        updates["display_name"] = name
    if body.kind is not None:
        updates["kind"] = _validated_kind(body.kind)
    if body.compliance_flags is not None:
        updates["compliance_flags"] = compliance_flags_json(_validated_flags(body.compliance_flags))
    if body.ai_policy is not None:
        updates["ai_policy"] = _validated_ai_policy(body.ai_policy, caller, tier=tier)
    if body.review_state is not None:
        if body.review_state != "confirmed":
            raise APIError(
                "VALIDATION_FAILED", "review_state can only be set to 'confirmed'",
            )
        updates["review_state"] = "confirmed"
    if not updates:
        raise APIError("VALIDATION_FAILED", "nothing to change")
    return updates


def _check_patch(row: sqlite3.Row, updates: dict[str, Any]) -> None:
    """The rules a PATCH obeys against the tenant as it stands.

    "Reviewed" means "a human said what it is": confirming needs a kind, and
    a confirmed tenant's kind never goes BACK to 'unclassified' — refused
    here with a 422 that says so, and by the registry itself since
    migration 034 (it moved the legacy confirmed + unclassified rows back to
    pending and refuses the combination with triggers). Any non-archived
    tenant may be confirmed: a disabled or offboarded one included, so none
    is left pending for ever."""
    slug = row["slug"]
    if row["status"] == "archived":
        raise APIError("CONFLICT", f"tenant {slug!r} is archived")
    effective_kind = updates.get("kind", row["kind"])
    if updates.get("review_state") == "confirmed" and effective_kind == "unclassified":
        raise APIError(
            "VALIDATION_FAILED",
            "set a kind (client / internal / dev / vendor / other) before confirming",
        )
    if row["review_state"] == "confirmed" and updates.get("kind") == "unclassified":
        raise APIError(
            "VALIDATION_FAILED",
            f"tenant {slug!r} is confirmed — its kind cannot go back to 'unclassified' "
            "(pick client / internal / dev / vendor / other)",
        )


def _changes(row: sqlite3.Row, updates: dict[str, Any]) -> list[FieldChangeOut]:
    """What `updates` would actually change on `row` (the audited shape)."""
    before = _snapshot(row)
    out: list[FieldChangeOut] = []
    for field, value in updates.items():
        after = parse_compliance_flags(value) if field == "compliance_flags" else value
        if after != before[field]:
            out.append(FieldChangeOut(field=field, before=before[field], after=after))
    return out


def _write_patch(
    conn: sqlite3.Connection, row: sqlite3.Row, updates: dict[str, Any], *,
    operator_id: int, reason: str, request_id: str | None = None,
    cloud_cleared: bool = False,
) -> tuple[list[int], ai_policy.AiPolicyStatus]:
    """Inside the caller's transaction: UPDATE, then — when the compliance
    flags changed — revoke the tenant's sign-off(s) ('flags_changed'), then
    ONE 'tenant_update' row with before/after (the effective AI policy on
    both sides, and the revoked sign-off ids). An audit failure raises and
    the caller's transaction rolls every write back — nothing stays changed
    unaudited. Returns (revoked sign-off ids, the effective policy after).
    `cloud_cleared`: the change passed `_cloud_clearance`'s bar (a stepped-up
    super_admin) — the row says so."""
    slug = row["slug"]
    before_policy = ai_policy.status_for_row(conn, row)
    sets = ", ".join(f"{k} = ?" for k in updates)
    conn.execute(f"UPDATE clients SET {sets} WHERE slug = ?", [*updates.values(), slug])
    invalidated: list[int] = []
    if "compliance_flags" in updates:
        invalidated = _invalidate_on_flag_change(
            conn, slug, row["compliance_flags"], updates["compliance_flags"],
            operator_id=operator_id,
        )
    new_row = _require_tenant(conn, slug)
    after_policy = ai_policy.status_for_row(conn, new_row)
    after: dict[str, Any] = {**_snapshot(new_row), "effective_ai_policy": after_policy.effective}
    if invalidated:
        after["compliance_signoffs_invalidated"] = invalidated
        reason = (
            f"{reason}; compliance sign-off(s) {', '.join(f'#{i}' for i in invalidated)} "
            "revoked: flags changed"
        )
    if cloud_cleared:
        after["cloud_clearance"] = {"step_up": True, "basis": after_policy.signoff.state}
        reason = f"{reason}; cleared for cloud AI by a super_admin under step-up"
    _audit_row(
        operator_id=operator_id, action="tenant_update", slug=slug,
        before={**_snapshot(row), "effective_ai_policy": before_policy.effective},
        after=after, reason=reason, request_id=request_id,
    )
    return invalidated, after_policy


@router.patch("/{slug}", response_model=TenantOut)
def patch_tenant(
    slug: str,
    body: PatchTenantRequest,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> TenantOut:
    """A change that would make the tenant run as cloud AI
    (`_cloud_clearance`) takes the sign-off's bar: 403 for an admin, and a
    super_admin's step-up — asked for BEFORE the write lock (step-up writes
    the registry), and the rule checked again under it."""
    tier = operator_max_tier(caller.operator_id)
    updates = _patch_updates(body, caller, tier=tier)
    stepped_up = False
    if "ai_policy" in updates or "compliance_flags" in updates:
        ro = connect(paths.registry_db_path(), read_only=True)
        ro.row_factory = sqlite3.Row
        try:
            row = _require_tenant(ro, slug)
            _check_patch(row, updates)
            clearance = _cloud_clearance(*_policy_change(ro, row, updates)[:2])
        finally:
            ro.close()
        if clearance:
            _require_cloud_bar(clearance, tier=tier, stepped_up=True)
            require_step_up(request, caller)
            stepped_up = True
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = _require_tenant(reg, slug)
            _check_patch(row, updates)
            clearance = _cloud_clearance(*_policy_change(reg, row, updates)[:2])
            if clearance:
                _require_cloud_bar(clearance, tier=tier, stepped_up=stepped_up)
            _write_patch(
                reg, row, updates, operator_id=caller.operator_id,
                reason="tenant updated via admin API", cloud_cleared=clearance is not None,
            )
        return _tenant_out(reg, _require_tenant(reg, slug), _instance_index())
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# Bulk review — many tenants, PATCH's rules, all-or-nothing
# ---------------------------------------------------------------------------

class _BulkRefused(Exception):
    """Unwinds the bulk transaction when a row fails validation — nothing
    was written, nothing audited."""


def _bulk_field_updates(
    items: list[BulkUpdateItem], caller: sessions.SessionInfo, *, tier: int,
) -> list[dict[str, Any] | APIError]:
    """PATCH's field validation for every item (no tenant read) — outside
    any registry transaction; the caller's tier is looked up once."""
    out: list[dict[str, Any] | APIError] = []
    for item in items:
        try:
            out.append(_patch_updates(item.patch, caller, tier=tier))
        except APIError as exc:
            out.append(exc)
    return out


def _ai_policy_note(
    before: ai_policy.AiPolicyStatus, after: ai_policy.AiPolicyStatus,
    invalidated: list[int], *, applied: bool, clearance: str | None = None,
) -> str | None:
    """The one line a bulk row shows about AI: which sign-offs its flag
    change revokes, and — never implying cloud is on when it is not, nor off
    when it stays on — that a 'cloud' tenant without a live sign-off runs as
    local until signed, or that it is (still) cleared for cloud on the
    'none' tag alone."""
    parts: list[str] = []
    if invalidated:
        ids = ", ".join(f"#{i}" for i in invalidated)
        parts.append(f"sign-off {ids} {'revoked' if applied else 'will be revoked'}: compliance flags change")
    if after.requested == "cloud" and after.effective != "cloud":
        parts.append(
            f"{'runs' if applied else 'will run'} as local until signed — "
            f"{ai_policy.why_not_cloud(after.flags, after.signoff)}"
        )
    elif after.effective == "cloud" and after.signoff.state == "not_required" and (
        invalidated or before.effective != "cloud"
    ):
        verb = ("stays" if before.effective == "cloud" else "is now") if applied else (
            "stays" if before.effective == "cloud" else "will be")
        parts.append(f"{verb} cleared for cloud AI — tagged 'none', no sign-off needed")
    elif after.effective != before.effective:
        parts.append(f"effective AI policy {before.effective} → {after.effective}")
    if clearance and not applied:
        parts.append("applying needs a super admin with step-up re-authentication")
    return "; ".join(parts) or None


def _preview_ai(
    conn: sqlite3.Connection, row: sqlite3.Row, updates: dict[str, Any], row_out: BulkRowOut,
    *, applied: bool, change: tuple[ai_policy.AiPolicyStatus, ai_policy.AiPolicyStatus, bool],
    clearance: str | None,
) -> None:
    """Fill a bulk row's AI fields from what the patch WILL do: the tenant's
    effective policy afterwards and the sign-offs a flag change revokes
    (`change` = `_policy_change` on the batch's own connection, before
    anything is written)."""
    if "ai_policy" not in updates and "compliance_flags" not in updates:
        return
    before, after, flags_change = change
    invalidated = ai_policy.unrevoked_signoff_ids(conn, row["slug"]) if flags_change else []
    row_out.effective_ai_policy = after.effective
    row_out.signoff = signoff_status_out(after.signoff)
    row_out.signoffs_invalidated = invalidated
    row_out.ai_policy_note = _ai_policy_note(
        before, after, invalidated, applied=applied, clearance=clearance,
    )


def _plan_bulk(
    conn: sqlite3.Connection, items: list[BulkUpdateItem],
    field_updates: list[dict[str, Any] | APIError], *, tier: int, applied: bool = False,
) -> tuple[list[BulkRowOut], list[tuple[sqlite3.Row, dict[str, Any]]]]:
    """Validate every row against the tenant as it stands on `conn` —
    exactly PATCH's rules, per row — and answer (the per-row diff with any
    error, the writes to make). A row whose tenant already says all that
    is reported unchanged and not written. Rows touching AI policy or flags
    say what the tenant will RUN with (`_preview_ai`); a row that would make
    a tenant run as cloud (`_cloud_clearance`) is refused for an admin
    (ISOLATION_VIOLATION) and marked `step_up_required` for a super_admin."""
    out: list[BulkRowOut] = []
    writes: list[tuple[sqlite3.Row, dict[str, Any]]] = []
    seen: set[str] = set()
    for item, updates in zip(items, field_updates):
        slug = item.slug.strip()
        row_out = BulkRowOut(slug=slug)
        out.append(row_out)
        try:
            if slug in seen:
                raise APIError("VALIDATION_FAILED", f"tenant {slug!r} is listed more than once")
            seen.add(slug)
            known = _tenant_row(conn, slug) if paths.SLUG_RE.match(slug) else None
            if known is not None:
                row_out.display_name, row_out.status = known["display_name"], known["status"]
            if isinstance(updates, APIError):
                raise updates                    # the field / role error comes first
            row = _require_tenant(conn, slug)
            _check_patch(row, updates)
            change = _policy_change(conn, row, updates)
            clearance = _cloud_clearance(*change[:2])
            if clearance:
                _require_cloud_bar(clearance, tier=tier, stepped_up=True)   # an admin: refused
        except APIError as exc:
            row_out.error = RowErrorOut(code=exc.code, message=exc.message)
            continue
        row_out.changes = _changes(row, updates)
        if row_out.changes:
            writes.append((row, updates))
            row_out.step_up_required = clearance is not None
        _preview_ai(conn, row, updates, row_out, applied=applied, change=change,
                    clearance=clearance)
    return out, writes


def _bulk_refusal(rows: list[BulkRowOut]) -> APIError | None:
    """One refusal for the batch as a whole, or None when every row is valid.
    Cloud for a non-super_admin wins — 'cloud' asked for, or a change that
    would make a tenant run as cloud: a role rule, not a typo, and the batch
    is refused for it even when every other row is fine."""
    failed = [r for r in rows if r.error is not None]
    if not failed:
        return None
    cloud = [r.slug for r in failed if r.error and r.error.code == "ISOLATION_VIOLATION"]
    if cloud:
        named = ", ".join(cloud[:5]) + (f" and {len(cloud) - 5} more" if len(cloud) > 5 else "")
        return APIError(
            "ISOLATION_VIOLATION",
            f"cloud AI (data may leave this deployment) requires super_admin — "
            f"{len(cloud)} row(s) in this batch ask for ai_policy 'cloud' or would make a "
            f"tenant run as cloud ({named}). Nothing was changed: remove those rows or ask a "
            "super admin to apply the batch.",
        )
    return APIError(
        "VALIDATION_FAILED",
        f"{len(failed)} of {len(rows)} row(s) cannot be applied (see each row's error). "
        "Nothing was changed — fix or drop those rows and apply again.",
    )


def _bulk_response(
    rows: list[BulkRowOut], *, dry_run: bool, applied: bool,
    request_id: str | None = None, refusal: APIError | None = None,
) -> BulkUpdateResponse:
    errors = sum(1 for r in rows if r.error is not None)
    changed = sum(1 for r in rows if r.error is None and r.changes)
    return BulkUpdateResponse(
        dry_run=dry_run, applied=applied, request_id=request_id, rows=rows,
        changed=changed, unchanged=len(rows) - errors - changed, errors=errors,
        refusal=RowErrorOut(code=refusal.code, message=refusal.message) if refusal else None,
        step_up_required=any(r.step_up_required for r in rows),
    )


@router.post("/bulk-update", response_model=BulkUpdateResponse)
def bulk_update_tenants(
    body: BulkUpdateRequest,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> Any:
    """Set kind / compliance flags / ai_policy and/or confirm on many tenants
    at once, under exactly PATCH's rules.

    ALL-OR-NOTHING, validated first: every row is checked against the
    registry inside ONE write transaction before anything is written; if
    any row fails, nothing is written and nothing is audited, and the answer
    (422, or 403 when a non-super_admin asked for 'cloud' anywhere in the
    batch) carries every row's own error so the operator can fix the batch
    and resubmit. A partial apply would leave a half-reviewed screen whose
    state no one chose. `dry_run` runs the same validation read-only and
    answers the per-row diff (200) — the console's preview — unaudited.

    Applied: one 'tenant_update' audit row per CHANGED tenant (PATCH's shape,
    before/after), all sharing the batch's request_id; a row that changes
    nothing is neither written nor audited. The audit log is a separate DB
    the registry transaction cannot roll back, so should an append fail
    part-way the registry is rolled back and a 'tenant_bulk_update_failed'
    row (error class only) names the tenants whose 'tenant_update' rows were
    already appended — the chain never says a change happened when it did
    not.

    A row that would make a tenant run as cloud AI takes the sign-off's bar
    (`_cloud_clearance`): an admin's batch is refused for it (403), a
    super_admin's needs an active step-up window — asked for once, BEFORE
    the write lock (step-up writes the registry)."""
    tier = operator_max_tier(caller.operator_id)
    field_updates = _bulk_field_updates(body.items, caller, tier=tier)
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        planned, _writes = _plan_bulk(reg, body.items, field_updates, tier=tier)
    finally:
        reg.close()
    if body.dry_run:
        return _bulk_response(
            planned, dry_run=True, applied=False, refusal=_bulk_refusal(planned),
        )
    stepped_up = False
    if _bulk_refusal(planned) is None and any(r.step_up_required for r in planned):
        require_step_up(request, caller)
        stepped_up = True

    request_id = str(uuid.uuid4())
    reason = f"tenant updated via bulk review ({len(body.items)} tenant(s) in the batch)"
    rows: list[BulkRowOut] = []
    refusal: APIError | None = None
    appended: list[str] = []
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        try:
            with transaction(reg):
                rows, writes = _plan_bulk(reg, body.items, field_updates, tier=tier, applied=True)
                refusal = _bulk_refusal(rows)
                if refusal is not None:
                    raise _BulkRefused()
                if not stepped_up and any(r.step_up_required for r in rows):
                    # Something changed since the read-only plan: nothing
                    # written; the console re-authenticates and retries.
                    raise APIError("STEP_UP_REQUIRED")
                by_slug = {r.slug: r for r in rows}
                try:
                    for row, updates in writes:
                        invalidated, after = _write_patch(
                            reg, row, updates, operator_id=caller.operator_id,
                            reason=reason, request_id=request_id,
                            cloud_cleared=by_slug[row["slug"]].step_up_required,
                        )
                        appended.append(row["slug"])
                        # What happened (the plan predicted it on this same
                        # transaction; the write's own answer is the record).
                        out = by_slug[row["slug"]]
                        out.signoffs_invalidated = invalidated
                        if out.effective_ai_policy is not None:
                            out.effective_ai_policy = after.effective
                            out.signoff = signoff_status_out(after.signoff)
                except Exception as exc:
                    if appended:
                        try:
                            _audit_row(
                                operator_id=caller.operator_id,
                                action="tenant_bulk_update_failed", slug="global",
                                target_kind="tenant_bulk_update", target_id=request_id,
                                after={"rolled_back": appended, "error": type(exc).__name__},
                                reason=f"bulk review failed: {type(exc).__name__}; every "
                                       "change in the batch was rolled back",
                                request_id=request_id,
                            )
                        except Exception:  # noqa: BLE001 — the audit log itself is failing
                            logger.error(
                                "[tenants] bulk update %s rolled back after %d audited "
                                "row(s); the failure row could not be appended either",
                                request_id, len(appended),
                            )
                    raise
        except _BulkRefused:
            assert refusal is not None
            # The error envelope every client understands ({code, message,
            # request_id}) plus the per-row answer the console shows.
            payload = _bulk_response(rows, dry_run=False, applied=False, refusal=refusal)
            return JSONResponse(
                status_code=refusal.status,
                content={
                    **payload.model_dump(mode="json"),
                    "code": refusal.code, "message": refusal.message,
                    "request_id": refusal.request_id,
                },
            )
    finally:
        reg.close()
    return _bulk_response(rows, dry_run=False, applied=True, request_id=request_id)


# ---------------------------------------------------------------------------
# Offboard / merge — direct or via change request
# ---------------------------------------------------------------------------

def _check_offboardable(conn: sqlite3.Connection, slug: str) -> sqlite3.Row:
    """The cheap preconditions of an offboard — run before ANY audit row is
    written, so a refused request never reads as an applied one."""
    row = _require_tenant(conn, slug)
    if row["status"] in ("offboarded", "archived"):
        raise APIError("CONFLICT", f"tenant {slug!r} is already {row['status']}")
    _refuse_open_incidents(slug)
    return row


def _refuse_open_incidents(slug: str) -> None:
    """A tenant with an OPEN Red / Black (Tier Black, 044) is never offboarded
    or merged away: the Fleet, the paging ladder and every incident route
    read ACTIVE tenants only, so the incident would vanish — paging stopped,
    nobody able to close it: a mute no person decided. Refused before any
    audit row; an incident store that cannot be read refuses too (never read
    as "none open")."""
    from apps.octo.threat import store as incident_store

    try:
        found = incident_store.list_incidents(slug, statuses=incident_store.OPEN_STATUSES,
                                              limit=1)
    except sqlite3.Error:
        raise APIError(
            "CONFLICT",
            f"tenant {slug!r}'s incident records could not be read — an open Red / Black "
            "cannot be ruled out; try again shortly",
        ) from None
    if found:
        raise APIError(
            "CONFLICT",
            f"tenant {slug!r} has an open {found[0].tier.upper()} incident (#{found[0].id}) — "
            "close or reclassify it first (an open incident is never offboarded or merged "
            "away)",
        )
    _refuse_open_ended_windows(slug)


def _refuse_open_ended_windows(slug: str) -> None:
    """A tenant with a HELD evidence window that has NO END (an admin's
    manual window "until released" — the former legal hold) is never
    offboarded or merged away: it keeps whatever of the client arrives until
    an admin releases it, and after an offboard (quarantined, evictable) or a
    merge (stored in the target, where no window covers it) nothing more
    would arrive under it — the hold would end without anyone deciding so.
    Give it an end first (add a window with an explicit end that covers it,
    then release the open one). Windows that cannot be read refuse too."""
    from apps.octo.retention import evidence as retention_evidence

    try:
        open_ended = [w for w in retention_evidence.held(paths.client_dir(slug))
                      if w.end is None]
    except retention_evidence.WindowsUnavailable:
        raise APIError(
            "CONFLICT",
            f"tenant {slug!r}'s evidence windows could not be read — an open-ended one "
            "cannot be ruled out; try again shortly",
        ) from None
    if open_ended:
        w = open_ended[0]
        raise APIError(
            "CONFLICT",
            f"tenant {slug!r} has an evidence window with no end (#{w.id}, incident "
            f"#{w.incident_id}, from {w.start}) — it keeps everything of this client until "
            "an admin releases it. Give it an end first (add a window with an explicit end "
            "covering it, then release the open one) — never offboarded or merged away "
            "while it is open",
        )


def _check_mergeable(
    conn: sqlite3.Connection, subject: str, target: str,
) -> tuple[sqlite3.Row, sqlite3.Row, int]:
    """The cheap preconditions of a merge (subject/target state, size, a
    target store to copy into) — before any audit row. Returns (subject row,
    target row, subject event count)."""
    if subject == target:
        raise APIError("VALIDATION_FAILED", "a tenant cannot be merged into itself")
    s_row = _require_tenant(conn, subject)
    t_row = _require_tenant(conn, target)
    if s_row["status"] == "archived":
        raise APIError("CONFLICT", f"tenant {subject!r} is already archived")
    if t_row["status"] != "active":
        raise APIError("CONFLICT", f"target tenant {target!r} is not active")
    # The merge archives the subject and copies only its events: its open
    # incident would leave every surface (`_refuse_open_incidents`).
    _refuse_open_incidents(subject)
    for row in (s_row, t_row):
        if not ai_policy.flags_readable(row["compliance_flags"]):
            # The union/eligibility rules would treat unreadable flags as
            # "untagged" and a regime could silently fall off the merged
            # tenant. Fix the tags first (Edit), then merge.
            raise APIError(
                "CONFLICT",
                f"tenant {row['slug']!r} has compliance flags this version cannot read — "
                "set its compliance tags under Edit before merging",
            )
    count, _ = _event_stats(subject)
    if count > MERGE_MAX_EVENTS:
        raise APIError(
            "CONFLICT",
            f"tenant {subject!r} holds {count} events, more than the {MERGE_MAX_EVENTS} "
            "a merge will move — this needs a maintenance job, not a click",
        )
    if not paths.client_db_path(target, "events").exists():
        raise APIError("CONFLICT", f"target tenant {target!r} has no events store")
    return s_row, t_row, count


def _scoped_operator_ids(conn: sqlite3.Connection, slug: str) -> list[int]:
    """Operators whose scope names this slug concretely — the tenant's own
    console users (viewers are client users). '*' scopes are the MSP's
    staff and are left alone."""
    ids: set[int] = set()
    for op_id, raw in conn.execute(
        "SELECT operator_id, scope_slugs FROM operator_roles",
    ).fetchall():
        try:
            scope = json.loads(raw) or []
        except (TypeError, ValueError):
            continue
        if isinstance(scope, list) and slug in scope:
            ids.add(int(op_id))
    return sorted(ids)


def _sever_client_access(
    conn: sqlite3.Connection, slug: str, *, operator_id: int, now: str,
) -> AccessSeveredOut:
    """Inside the caller's transaction. Everything that let the tenant's own
    side in stops working: buoy/API tokens revoked, live sessions of client
    users scoped to it ended (their next request is a 401 → sign-in; the
    scope filter in the dashboard/search routes shows them nothing even
    before that), and the count of such accounts reported so the operator
    removes them under Operators. Instance defaults that pointed at it are
    cleared (an id-less event must never land in a departed tenant)."""
    tokens = conn.execute(
        "UPDATE client_tokens SET revoked_at = ?, revoked_by = ? "
        "WHERE slug = ? AND revoked_at IS NULL", (now, str(operator_id), slug),
    ).rowcount
    scoped = _scoped_operator_ids(conn, slug)
    revoked = 0
    if scoped:
        marks = ",".join("?" * len(scoped))
        revoked = conn.execute(
            f"UPDATE sessions SET revoked_at = ?, revoked_by = ? "
            f"WHERE operator_id IN ({marks}) AND revoked_at IS NULL",
            (now, operator_id, *scoped),
        ).rowcount
    defaults = conn.execute(
        "UPDATE adapter_instances SET default_tenant_slug = NULL "
        "WHERE default_tenant_slug = ?", (slug,),
    ).rowcount
    return AccessSeveredOut(
        tokens_revoked=int(tokens), sessions_revoked=int(revoked),
        scoped_operators=len(scoped), instance_defaults_cleared=int(defaults),
    )


def _cancel_pending_requests_touching(
    conn: sqlite3.Connection, slug: str, *, operator_id: int, now: str, note: str,
) -> None:
    """A pending request whose subject OR target just left can never be
    applied: cancel it so it neither locks the other tenant nor sits in the
    queue for ever."""
    conn.execute(
        "UPDATE tenant_change_requests SET state = 'cancelled', decided_by = ?, "
        "decided_at = ?, decision_note = ? "
        "WHERE (subject_slug = ? OR target_slug = ?) AND state = 'pending'",
        (operator_id, now, note, slug, slug),
    )


def _apply_offboard(
    conn: sqlite3.Connection, slug: str, *, operator_id: int, reason: str,
    request_id: str, approval: dict[str, Any] | None = None,
) -> tuple[int, AccessSeveredOut, list[int]]:
    """Inside the caller's transaction. Status → offboarded; mappings KEPT
    pointing at the offboarded slug (frozen: the site's next event holds as
    'offboarded-tenant' — deleting them would let a site whose vendor name
    differs from the display name auto-create a look-alike tenant); client
    access severed; its cloud-AI sign-offs revoked (the relationship, and
    the consent, ended — it runs as 'none' from now: `ai_policy`). Data is
    retained. Returns (mappings frozen, access, sign-offs revoked).
    `approval` ({approval_mode, change_request_id}) is recorded in the
    'tenant_offboard' row: HOW this was approved."""
    row = _check_offboardable(conn, slug)
    before = _snapshot(row)
    now = utcnow_iso()
    mappings = conn.execute(
        "SELECT COUNT(*) FROM adapter_tenant_map WHERE octo_client_slug = ?", (slug,),
    ).fetchone()[0]
    scoped = _scoped_operator_ids(conn, slug)
    to_revoke = ai_policy.unrevoked_signoff_ids(conn, slug)
    _audit_row(
        operator_id=operator_id, action="tenant_offboard", slug=slug,
        before=before,
        after={**before, "status": "offboarded", "mappings_frozen": int(mappings),
               "scoped_operators": scoped, "effective_ai_policy": "none",
               "compliance_signoffs_revoked": to_revoke, **(approval or {})},
        reason=reason, request_id=request_id,
    )
    conn.execute(
        "UPDATE clients SET status = 'offboarded', offboarded_at = ? WHERE slug = ?",
        (now, slug),
    )
    revoked = ai_policy.invalidate_signoffs(
        conn, slug, operator_id=operator_id, kind="operator",
        reason="tenant offboarded — no model reasons over a departed tenant's data",
    )
    access = _sever_client_access(conn, slug, operator_id=operator_id, now=now)
    _cancel_pending_requests_touching(
        conn, slug, operator_id=operator_id, now=now, note="superseded: tenant offboarded",
    )
    return int(mappings), access, revoked


class _CopiedEvents:
    """The rows a merge inserted into the target's events.db — a store the
    registry transaction cannot roll back. Whoever owns that transaction
    creates one, passes it to `_apply_merge`, and — should ANYTHING after
    the copy fail (the rest of the merge, its audit rows, a notice, the
    registry COMMIT) — calls `_undo_merge_copy`: exactly these rows are
    deleted again, so a merge that did not happen leaves none of the
    subject's data in the target (under a policy or tags that never
    covered it)."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.ids: list[int] = []

    def undo(self) -> tuple[int, int, str | None]:
        """Delete the recorded rows (and any agent note the triage worker
        wrote on them meanwhile), in one transaction on the target's store.
        Returns (removed, left in the target, error class or None)."""
        if not self.ids:
            return 0, 0, None
        try:
            dst = sqlite3.connect(paths.client_db_path(self.target, "events"), timeout=10.0)
        except Exception as exc:  # noqa: BLE001
            return 0, len(self.ids), type(exc).__name__
        removed = 0
        try:
            dst.execute("BEGIN IMMEDIATE")
            try:
                for i in range(0, len(self.ids), _MERGE_BATCH):
                    chunk = self.ids[i:i + _MERGE_BATCH]
                    marks = ",".join("?" * len(chunk))
                    removed += dst.execute(
                        f"DELETE FROM events WHERE id IN ({marks})", chunk,
                    ).rowcount
                    try:
                        dst.execute(
                            f"DELETE FROM agent_notes WHERE ref_kind = 'event' "
                            f"AND ref_id IN ({marks})", chunk,
                        )
                    except sqlite3.OperationalError:   # a store without agent_notes
                        pass
                dst.execute("COMMIT")
            except Exception:
                dst.execute("ROLLBACK")
                raise
        except Exception as exc:  # noqa: BLE001 — reported; the caller fails closed
            return 0, len(self.ids), type(exc).__name__
        finally:
            dst.close()
        self.ids = []
        return removed, 0, None


def _undo_merge_copy(
    copied: _CopiedEvents | None, *, subject: str, operator_id: int, request_id: str,
) -> None:
    """After a merge failed with the registry rolled back: remove the rows it
    copied into the target (`_CopiedEvents.undo`). Should that fail too (the
    target store is what broke), fail CLOSED on what stays: the subject's
    regimes are unioned onto the target (`ai_policy.merged_flags`) and the
    target's sign-offs revoked ('merge_added_flags') in a transaction of
    their own — extra tags and a revoked sign-off are safe; regulated data
    under tags that never covered it is not. Audited
    'tenant_merge_copy_undone' (counts and error classes only). Never
    raises: the merge's own error is the one the caller re-raises."""
    if copied is None or not copied.ids:
        return
    target = copied.target
    copied_n = len(copied.ids)
    removed, left, error = copied.undo()
    after: dict[str, Any] = {
        "target": target, "events_copied": copied_n, "events_removed": removed,
        "events_left_in_target": left, "error": error,
    }
    reason = (f"merge into {target} failed after copying {copied_n} event(s); "
              f"{removed} removed from the target again")
    if left:
        try:
            reg = connect(paths.registry_db_path())
            reg.row_factory = sqlite3.Row
            try:
                with transaction(reg):
                    s_row, t_row = _require_tenant(reg, subject), _require_tenant(reg, target)
                    t_flags = ai_policy.canonical_flags(t_row["compliance_flags"])
                    new_flags = ai_policy.merged_flags(
                        ai_policy.canonical_flags(s_row["compliance_flags"]), t_flags,
                    )
                    revoked: list[int] = []
                    if new_flags != t_flags:
                        reg.execute(
                            "UPDATE clients SET compliance_flags = ? WHERE slug = ?",
                            (compliance_flags_json(new_flags), target),
                        )
                        revoked = ai_policy.invalidate_signoffs(
                            reg, target, operator_id=operator_id, kind="merge_added_flags",
                            reason=f"a failed merge of {subject} left {left} of its events here",
                        )
                    after.update({"target_compliance_flags": new_flags,
                                  "target_signoffs_revoked": revoked})
                    _audit_row(
                        operator_id=operator_id, action="tenant_merge_copy_undone", slug=subject,
                        after=after, request_id=request_id,
                        reason=(f"{reason}; {left} could not be removed — {target} now tagged "
                                f"{ai_policy.flags_label(new_flags)}, sign-off(s) revoked: "
                                f"{revoked or 'none'} (fail closed)"),
                    )
            finally:
                reg.close()
            return
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "[tenants] merge %s: %d copied event(s) left in %s and the fail-closed "
                "re-tag failed (%s)", request_id, left, target, type(exc).__name__,
            )
            after["fail_closed_error"] = type(exc).__name__
    try:
        _audit_row(
            operator_id=operator_id, action="tenant_merge_copy_undone", slug=subject,
            after=after, request_id=request_id, reason=reason,
        )
    except Exception as exc:  # noqa: BLE001 — the audit log itself is failing
        logger.error("[tenants] merge %s: copy-undo audit row not written (%s)",
                     request_id, type(exc).__name__)


def _copy_events(
    subject: str, target: str, record: _CopiedEvents,
    subject_onboarded_at: Optional[str] = None,
) -> tuple[int, int]:
    """Copy the subject's events into the target's events.db with the sink's
    idempotency identity (payload_sha256 + source + received_at): a row the
    target already holds is skipped, and so is Athena's own incident record
    (`athena.incident` — it stays with the subject's incidents). Each
    committed batch's new row ids go into `record` (a failed batch rolls back
    and records none). Returns (copied, skipped)."""
    src_path = paths.client_db_path(subject, "events")
    dst_path = paths.client_db_path(target, "events")
    if not src_path.exists():
        return 0, 0
    if not dst_path.exists():
        raise APIError("CONFLICT", f"target tenant {target!r} has no events store")
    src = connect(src_path, read_only=True)
    dst = sqlite3.connect(dst_path, timeout=10.0)
    dst.row_factory = sqlite3.Row
    try:
        # A copy keeps the row's ARRIVAL (retention ages it by that, 036): its
        # stamp, else — stored before 036 — the estimate the backfill would
        # give it (`arrival.Estimator`, fed the subject's rows in id order:
        # the stamp a 036 rollback kept for it, else its received_at; never
        # before an earlier row's arrival nor the SUBJECT's onboarding — its
        # rows cannot have arrived before it existed — never later than now).
        arrival.add_column(dst)
        src_cols = [r[1] for r in src.execute("PRAGMA table_info(events)")]
        dst_cols = {r[1] for r in dst.execute("PRAGMA table_info(events)")}
        cols = [c for c in src_cols
                if c in dst_cols and c not in ("id", arrival.COLUMN)] + [arrival.COLUMN]
        col_sql = ", ".join(cols)
        stamp_sql = arrival.COLUMN if arrival.has_column(src) else "NULL"
        select_sql = ", ".join(
            [c for c in cols if c != arrival.COLUMN]
            + [f"{stamp_sql} AS _arrival_stamp", "payload_sha256 AS _arrival_sha"]
        )
        estimator = arrival.Estimator(
            utcnow_iso(), arrival.onboarded_floor(subject_onboarded_at))
        copied = skipped = 0
        last_id = 0
        while True:
            batch = src.execute(
                f"SELECT id, {select_sql} FROM events WHERE id > ? ORDER BY id LIMIT ?",
                (last_id, _MERGE_BATCH),
            ).fetchall()
            if not batch:
                break
            kept = arrival.preserved_stamps(src, int(batch[0]["id"]), int(batch[-1]["id"]))
            arrived: dict[int, str] = {}
            for r in batch:
                if r["_arrival_stamp"] is not None:
                    arrived[int(r["id"])] = estimator.stamped(r["_arrival_stamp"])
                else:
                    arrived[int(r["id"])] = estimator.estimate(
                        r["received_at"],
                        arrival.match_preserved(kept.get(int(r["id"])), r["_arrival_sha"]),
                    )
            dst.execute("BEGIN IMMEDIATE")
            inserted: list[int] = []
            try:
                for r in batch:
                    last_id = int(r["id"])
                    if r["source"] == "athena":
                        # Athena's own incident records (`athena.incident`)
                        # belong to the SUBJECT's incidents, which stay with
                        # it (a merge is refused while one is open).
                        skipped += 1
                        continue
                    dup = dst.execute(
                        "SELECT 1 FROM events WHERE payload_sha256 = ? AND source = ? "
                        "AND received_at = ? LIMIT 1",
                        (r["payload_sha256"], r["source"], r["received_at"]),
                    ).fetchone()
                    if dup:
                        skipped += 1
                        continue
                    cur = dst.execute(
                        f"INSERT INTO events ({col_sql}) VALUES ({', '.join('?' * len(cols))})",
                        [arrived[last_id] if c == arrival.COLUMN else r[c] for c in cols],
                    )
                    inserted.append(int(cur.lastrowid))
                dst.execute("COMMIT")
            except Exception:
                dst.execute("ROLLBACK")
                raise
            copied += len(inserted)
            record.ids.extend(inserted)
        return copied, skipped
    finally:
        src.close()
        dst.close()


def _apply_merge(
    conn: sqlite3.Connection, subject: str, target: str, *, operator_id: int,
    reason: str, request_id: str, copied: _CopiedEvents,
    approval: dict[str, Any] | None = None,
) -> MergeResponse:
    """Inside the caller's registry transaction. Mappings and instance
    defaults re-pointed at the target, the target's compliance flags and
    sign-offs settled, subject archived (its own sign-offs revoked) and its
    client access severed (its buoys/tokens stop; the target needs its own),
    and — LAST — events copied (idempotent); indicators/audit untouched.

    The copy is the one step the registry transaction cannot roll back, so
    it runs after every registry write (a failed copy rolls those back) and
    records the rows it inserts in `copied`, which the CALLER undoes should
    anything after it fail — this function's audit row, the caller's own
    rows, the COMMIT (`_undo_merge_copy`).

    Unlike the other lifecycle writes, the 'tenant_merge' audit row is
    written LAST: an audit row appended before the copy claimed "archived,
    merged into X" for a merge the caller then rolled back. On failure a
    'tenant_merge_failed' row (error class only — never a path or a
    message) keeps the attempt on record; the caller's transaction restores
    the registry, the subject stays as it was, and the copy being idempotent
    a retry after repair completes the merge. Should the success row itself
    fail to append, the exception still unwinds the caller's transaction:
    nothing stays changed unaudited. `approval` ({approval_mode,
    change_request_id}) is recorded in the 'tenant_merge' row: HOW this
    merge was approved."""
    s_row, t_row, count = _check_mergeable(conn, subject, target)
    scoped = _scoped_operator_ids(conn, subject)
    t_policy_before = ai_policy.status_for_row(conn, t_row)
    before = {
        "subject": _snapshot(s_row),
        "target": {**_snapshot(t_row), "effective_ai_policy": t_policy_before.effective},
    }
    s_flags = ai_policy.canonical_flags(s_row["compliance_flags"])
    t_flags = ai_policy.canonical_flags(t_row["compliance_flags"])
    flags_added = ai_policy.regimes_not_covered(s_flags, t_flags)
    new_flags = ai_policy.merged_flags(s_flags, t_flags)
    now = utcnow_iso()
    try:
        mappings = conn.execute(
            "UPDATE adapter_tenant_map SET octo_client_slug = ?, updated_at = ?, "
            "updated_by_operator_id = ? WHERE octo_client_slug = ?",
            (target, now, operator_id, subject),
        ).rowcount
        defaults = conn.execute(
            "UPDATE adapter_instances SET default_tenant_slug = ? WHERE default_tenant_slug = ?",
            (target, subject),
        ).rowcount
        # The subject's data now lives in the target: a compliance regime
        # the subject carried and the target did not is unioned onto the
        # target — and an untagged subject takes a 'none' target back to []
        # (`ai_policy.merged_flags`) — and the target's sign-off, which never
        # covered that, is revoked ('merge_added_flags').
        invalidated: list[int] = []
        if new_flags != t_flags:
            conn.execute(
                "UPDATE clients SET compliance_flags = ? WHERE slug = ?",
                (compliance_flags_json(new_flags), target),
            )
            invalidated = ai_policy.invalidate_signoffs(
                conn, target, operator_id=operator_id, kind="merge_added_flags",
                reason=(f"merge of {subject} added {ai_policy.flags_label(flags_added)}"
                        if flags_added else
                        f"merge of {subject} brought never-tagged data: 'none' no longer holds"),
            )
        conn.execute(
            "UPDATE clients SET status = 'archived', archived_at = ?, notes = ? WHERE slug = ?",
            (now, f"merged into {target}", subject),
        )
        subject_revoked = ai_policy.invalidate_signoffs(
            conn, subject, operator_id=operator_id, kind="operator",
            reason=f"tenant merged into {target} and archived",
        )
        access = _sever_client_access(conn, subject, operator_id=operator_id, now=now)
        access.instance_defaults_cleared = int(defaults)   # re-pointed, for a merge
        _cancel_pending_requests_touching(
            conn, subject, operator_id=operator_id, now=now, note="superseded: tenant merged",
        )
        copied_n, skipped = _copy_events(
            subject, target, copied, subject_onboarded_at=s_row["onboarded_at"])
    except Exception as exc:
        # The type names the failure; its message could carry a path.
        _audit_row(
            operator_id=operator_id, action="tenant_merge_failed", slug=subject,
            before=before,
            after={"subject_status": s_row["status"], "merged_into": None,
                   "error": type(exc).__name__},
            reason=f"merge failed: {type(exc).__name__}; registry changes rolled back, "
                   "nothing archived",
            request_id=request_id,
        )
        raise
    t_policy_after = ai_policy.status_for_row(conn, _require_tenant(conn, target))
    after: dict[str, Any] = {
        "subject_status": "archived", "merged_into": target,
        "events_in_subject": count, "events_copied": copied_n,
        "events_skipped": skipped, "mappings_repointed": int(mappings),
        "scoped_operators": scoped,
        "target_compliance_flags": list(t_policy_after.flags),
        "target_effective_ai_policy": t_policy_after.effective,
        "subject_signoffs_revoked": subject_revoked,
        **(approval or {}),
    }
    if new_flags != t_flags:
        after["target_flags_added"] = flags_added
        after["compliance_signoffs_invalidated"] = invalidated
        change = (f"added {ai_policy.flags_label(flags_added)} to {target}" if flags_added
                  else f"took {target} from ['none'] back to [] (never-tagged data)")
        reason = (
            f"{reason}; merge {change}"
            + (f", compliance sign-off(s) {', '.join(f'#{i}' for i in invalidated)} revoked"
               if invalidated else "")
        )
    _audit_row(
        operator_id=operator_id, action="tenant_merge", slug=subject,
        before=before, after=after, reason=reason, request_id=request_id,
    )
    return MergeResponse(
        slug=subject, target=target, applied=True, status="archived",
        mappings_repointed=int(mappings), events_copied=copied_n, events_skipped=skipped,
        access=access, target_flags_added=flags_added, target_flags_after=new_flags,
        signoffs_invalidated=invalidated, subject_signoffs_revoked=subject_revoked,
    )


def _create_request(
    conn: sqlite3.Connection, *, kind: str, subject: str, target: str | None,
    operator_id: int, reason: str, request_id: str,
) -> ChangeRequestOut:
    """A two-person change request (the default for offboard and merge)."""
    if _pending_request_for(conn, subject) is not None:
        raise APIError("CONFLICT", f"tenant {subject!r} already has a pending change request")
    _audit_row(
        operator_id=operator_id, action="tenant_change_request_create", slug=subject,
        after={"kind": kind, "subject_slug": subject, "target_slug": target, "state": "pending",
               "approval_mode": "two_person"},
        reason=reason, request_id=request_id, target_kind="tenant_change_request",
    )
    cur = conn.execute(
        "INSERT INTO tenant_change_requests (kind, subject_slug, target_slug, requested_by, "
        "reason, state, request_id, approval_mode) VALUES (?, ?, ?, ?, ?, 'pending', ?, "
        "'two_person')",
        (kind, subject, target, operator_id, clean_line(reason, MAX_REASON), request_id),
    )
    row = conn.execute(
        "SELECT * FROM tenant_change_requests WHERE id = ?", (cur.lastrowid,),
    ).fetchone()
    return _request_out(row)


# ---------------------------------------------------------------------------
# The attested single-person exception (v0.10 item 7)
# ---------------------------------------------------------------------------

def _require_attestation(
    body: LifecycleActionRequest, slug: str, *, is_super: bool, kind: str,
) -> str:
    """What the BODY must carry for a single-person offboard / merge, in
    order, each refusal naming the one missing piece (nothing is read or
    written before these pass). Returns the attestation, verbatim."""
    verb = "merge" if kind == "merge" else "offboard"
    if not is_super:
        raise APIError(
            "ISOLATION_VIOLATION",
            f"only a super_admin may {verb} a tenant alone (approval_mode 'single_attested'); "
            "an admin files a two-person request (approval_mode 'two_person')",
        )
    attestation = body.attestation or ""
    typed = len(attestation.strip())
    if typed < ATTESTATION_MIN_CHARS:
        raise APIError(
            "ATTESTATION_REQUIRED",
            f"a single-person {verb} needs a typed attestation of at least "
            f"{ATTESTATION_MIN_CHARS} characters ({typed} given): why it cannot wait for a "
            "second approver, and that you checked what it does",
        )
    if body.confirm_subject != slug:
        raise APIError(
            "SUBJECT_CONFIRMATION_MISMATCH",
            f"confirm_subject must be exactly {slug!r} — the tenant that will be "
            f"{'archived' if kind == 'merge' else 'offboarded'}",
        )
    return attestation


def _other_super_admins(conn: sqlite3.Connection, caller_id: int) -> int:
    """Active super_admins other than the caller — who could approve a
    two-person request."""
    return int(conn.execute(
        "SELECT COUNT(*) FROM operators o WHERE o.id != ? AND o.disabled_at IS NULL "
        "AND o.removed_at IS NULL AND EXISTS (SELECT 1 FROM operator_roles r "
        "WHERE r.operator_id = o.id AND r.role_name = 'super_admin')", (caller_id,),
    ).fetchone()[0])


def _single_person_merge_eligibility(
    conn: sqlite3.Connection, s_row: sqlite3.Row, t_row: sqlite3.Row, *, caller_id: int,
) -> SinglePersonEligibilityOut:
    """The owner's guards (2026-09-28) on the single-person merge, on
    EFFECTIVE policies (`ai_policy.status_for_row` — what
    `effective_ai_policy` answers, read on this connection so the check sits
    inside the caller's transaction): the target may not run AI more
    permissively than the subject (none < local < cloud) — the subject's
    events would be reasoned over by a model its own standing does not
    allow — and the subject may not carry a compliance regime the target
    lacks (the merge would add it to the target and revoke the target's
    sign-off). Also: the subject must be ACTIVE — an offboarded subject's
    frozen site mappings would be re-pointed into the target, un-freezing a
    departed client's traffic. Any one: two people decide. Each reason says
    what would make the single-person path apply (`remedy`), and the answer
    counts who could approve the two-person request."""
    subject, target = s_row["slug"], t_row["slug"]
    s_pol = ai_policy.status_for_row(conn, s_row)
    t_pol = ai_policy.status_for_row(conn, t_row)
    missing = ai_policy.regimes_not_covered(s_pol.flags, t_pol.flags)
    # Would the pair qualify the other way round (target merged into subject)?
    reverse_ok = (
        s_row["status"] == "active"
        and ai_policy.policy_rank(s_pol.effective) <= ai_policy.policy_rank(t_pol.effective)
        and not ai_policy.regimes_not_covered(t_pol.flags, s_pol.flags)
    )
    reverse = f"merge {target} into {subject} instead (keeps {subject})" if reverse_ok else None
    reasons: list[EligibilityReasonOut] = []
    if s_row["status"] != "active":
        reasons.append(EligibilityReasonOut(
            code="subject_not_active",
            message=(
                f"{subject} is {s_row['status']} — its frozen site mappings would be re-pointed "
                f"into {target}, bringing a departed client's traffic back"
            ),
        ))
    if ai_policy.policy_rank(t_pol.effective) > ai_policy.policy_rank(s_pol.effective):
        unsigned = (
            s_row["status"] == "active" and s_pol.requested == "cloud"
            and s_pol.effective != "cloud"
        )
        if unsigned:
            message = (
                f"{target} runs AI as '{t_pol.effective}'; {subject} asks for 'cloud' but runs as "
                f"'{s_pol.effective}' ({ai_policy.why_not_cloud(s_pol.flags, s_pol.signoff)})"
            )
            fixes = [f"sign {subject} off for {ai_policy.flags_label(s_pol.flags)} first"]
        else:
            message = (
                f"{target} runs AI as '{t_pol.effective}', more permissive than {subject}'s "
                f"'{s_pol.effective}' — {subject}'s events would be reasoned over under a policy "
                "its own does not allow"
            )
            fixes = ([f"set {subject}'s AI policy to '{t_pol.effective}' first, if its data may "
                      "be processed that way"] if s_row["status"] == "active" else [])
        if reverse:
            fixes.append(reverse)
        reasons.append(EligibilityReasonOut(
            code="target_ai_more_permissive", message=message,
            remedy=" — or ".join(fixes) or None,
        ))
    if missing:
        fixes = [f"tag {target} with {ai_policy.flags_label(missing)} first (that revokes "
                 f"{target}'s cloud-AI sign-off, if it has one)"]
        if reverse:
            fixes.append(reverse)
        reasons.append(EligibilityReasonOut(
            code="subject_flags_not_on_target",
            message=(
                f"{subject} is tagged {ai_policy.flags_label(missing)} and {target} is not — "
                f"the merge would add {'that regime' if len(missing) == 1 else 'those regimes'} "
                f"to {target}"
            ),
            remedy=" — or ".join(fixes),
        ))
    return SinglePersonEligibilityOut(
        eligible=not reasons, reasons=reasons,
        subject_effective_ai_policy=s_pol.effective,
        target_effective_ai_policy=t_pol.effective,
        subject_flags_not_on_target=missing,
        other_super_admins=_other_super_admins(conn, caller_id),
    )


def _ineligible(e: SinglePersonEligibilityOut) -> APIError:
    """The refusal names every guard that applies, what would make the
    single-person path apply, and whether the two-person request is a way
    out at all — it is not when no other super_admin exists to approve it."""
    parts = []
    for r in e.reasons:
        parts.append(r.message + (f". To merge alone: {r.remedy}" if r.remedy else ""))
    if e.other_super_admins:
        fallback = (
            "Or file a two-person request (approval_mode 'two_person') — a super admin other "
            "than you approves it."
        )
    else:
        fallback = (
            "A two-person request (approval_mode 'two_person') needs a super admin other than "
            "you to approve it, and this deployment has none."
        )
    return APIError(
        "SINGLE_PERSON_INELIGIBLE",
        "single-person merge refused: " + "; ".join(parts) + ". " + fallback,
    )


def _check_no_pending_merge_requests(conn: sqlite3.Connection, subject: str, target: str) -> None:
    if _pending_request_for(conn, target) is not None:
        raise APIError("CONFLICT", f"target tenant {target!r} has a pending change request")
    if _pending_request_for(conn, subject) is not None:
        raise APIError("CONFLICT", f"tenant {subject!r} already has a pending change request")


def _insert_attested_record(
    conn: sqlite3.Connection, *, kind: str, subject: str, target: str | None,
    operator_id: int, reason: str, attestation: str, confirmation: str, request_id: str,
    now: str,
) -> int:
    """The change record of a single-person change: applied by its own
    requester, the attestation verbatim, the slug as typed, a post-review
    pending (optional — by a second admin+)."""
    cur = conn.execute(
        "INSERT INTO tenant_change_requests (kind, subject_slug, target_slug, requested_by, "
        "requested_at, reason, state, decided_by, decided_at, decision_note, request_id, "
        "approval_mode, attestation, subject_confirmation, post_review_state) "
        "VALUES (?, ?, ?, ?, ?, ?, 'applied', ?, ?, ?, ?, 'single_attested', ?, ?, 'pending')",
        (kind, subject, target, operator_id, now, clean_line(reason, MAX_REASON), operator_id,
         now, "applied alone — attested single-person exception", request_id, attestation,
         confirmation),
    )
    return int(cur.lastrowid)


def _notice_text(
    conn: sqlite3.Connection, *, kind: str, actor_id: int, subject: str,
    target: str | None, change_request_id: int, reason: str, now: str,
) -> tuple[str, str]:
    actor = conn.execute("SELECT username FROM operators WHERE id = ?", (actor_id,)).fetchone()
    who = f"{actor['username']} (operator #{actor_id})" if actor else f"operator #{actor_id}"
    if kind == "merge":
        title = f"Single-person merge: {subject} → {target}"
        what = f"merged {subject} into {target} ({subject} is archived)"
    else:
        title = f"Single-person offboard: {subject}"
        what = f"offboarded {subject}"
    body = (
        f"{who} {what} alone, on a typed attestation, at {now[:19].replace('T', ' ')} UTC — "
        f"no second approver. Reason: {clean_line(reason, MAX_REASON)}. Change request "
        f"#{change_request_id}: read the attestation and record a post-review under "
        "Settings → Tenants → Single-person changes."
    )
    return title, body


def _attested_marker(
    *, kind: str, operator_id: int, subject: str, target: str | None,
    change_request_id: int, reason: str, request_id: str, attestation: str,
    confirmation: str, notified: operator_notices.NoticeBatch,
    extra: dict[str, Any] | None = None,
) -> None:
    """The loud, filterable audit row of a single-person change —
    'tenant_merge_single_attested' / 'tenant_offboard_single_attested' —
    written last, inside the transaction. The attestation's sha256 and
    length, never its text (that lives on the change record). Should the
    marker fail to append, a '<kind>_failed' row says the change was rolled
    back (the chain already holds the success row) and the error unwinds
    the caller's transaction."""
    try:
        _audit_row(
            operator_id=operator_id, action=f"tenant_{kind}_single_attested", slug=subject,
            target_kind="tenant_change_request", target_id=str(change_request_id),
            after={
                "approval_mode": "single_attested", "kind": kind,
                "change_request_id": change_request_id,
                "subject_slug": subject, "target_slug": target,
                "attestation_sha256": ai_policy.attestation_sha256(attestation),
                "attestation_chars": len(attestation),
                "subject_confirmation": confirmation, "step_up": True,
                "post_review_state": "pending",
                "notified": notified.audit_json(),
                **(extra or {}),
            },
            reason=(
                f"SINGLE-PERSON {kind.upper()} — attested exception, no second approver: "
                f"{reason}"
            ),
            request_id=request_id,
        )
    except Exception as exc:
        try:
            _audit_row(
                operator_id=operator_id, action=f"tenant_{kind}_failed", slug=subject,
                after={"approval_mode": "single_attested", "change_request_id": None,
                       "error": type(exc).__name__},
                reason=f"the single-person audit marker could not be written: "
                       f"{type(exc).__name__}; registry changes rolled back",
                request_id=request_id,
            )
        except Exception:  # noqa: BLE001 — the original error is the one to raise
            logger.error("single-person %s: audit unavailable (%s)", kind, type(exc).__name__)
        raise


def _queue_notice_email(
    background: BackgroundTasks, batch: operator_notices.NoticeBatch, *, kind: str,
    actor_id: int, subject: str, change_request_id: int, request_id: str,
) -> str:
    """The e-mail copy runs AFTER the response (never under the registry
    lock, never able to fail the change); it records its own outcome."""
    if not batch.notice_ids:
        return "none"
    background.add_task(
        operator_notices.email_notices, list(batch.notice_ids),
        kind=f"single_attested_{kind}", actor_id=actor_id, subject_slug=subject,
        change_request_id=change_request_id, request_id=request_id,
    )
    return "queued"


def _count_rows(slug: str, db: str, table: str) -> int:
    """COUNT(*) of one table in one of the tenant's stores; 0 when the store
    or table is absent or busy."""
    try:
        db_path = paths.client_db_path(slug, db)
    except Exception:  # noqa: BLE001 — a slug the path layer refuses
        return 0
    if not db_path.exists():
        return 0
    try:
        conn = connect(db_path, read_only=True)
    except Exception:  # noqa: BLE001
        return 0
    try:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    except sqlite3.OperationalError:
        return 0
    finally:
        conn.close()


# What a merge leaves on the archived subject (`_copy_events` copies the
# `events` table only): (label, store, table).
_LEFT_BEHIND: tuple[tuple[str, str, str], ...] = (
    ("incidents", "events", "incidents"),
    ("agent_notes", "events", "agent_notes"),
    ("indicators", "indicators", "indicators"),
    ("tickets", "tickets", "tickets"),
)


# ---------------------------------------------------------------------------
# Offboard / merge routes
# ---------------------------------------------------------------------------

@router.post("/{slug}/offboard", response_model=OffboardResponse)
def offboard_tenant(
    slug: str,
    body: LifecycleActionRequest,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> OffboardResponse:
    """Two-person by default: a change request a super_admin other than the
    requester approves (202). A super_admin may instead apply it alone as the
    attested exception (approval_mode 'single_attested', 200) — see the
    module docstring for what that needs and records."""
    request_id = str(uuid.uuid4())
    is_super = operator_max_tier(caller.operator_id) >= ROLE_TIER["super_admin"]
    if body.approval_mode == "single_attested":
        attestation = _require_attestation(body, slug, is_super=is_super, kind="offboard")
        # The cheap preconditions BEFORE the re-authentication prompt.
        ro = connect(paths.registry_db_path(), read_only=True)
        ro.row_factory = sqlite3.Row
        try:
            _check_offboardable(ro, slug)
        finally:
            ro.close()
        # Outside any registry transaction: step-up writes the registry.
        require_step_up(request, caller)
        return _offboard_attested(
            slug, reason=body.reason, attestation=attestation, caller=caller,
            request_id=request_id, background=background,
        )
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = _check_offboardable(reg, slug)
            req = _create_request(
                reg, kind="offboard", subject=slug, target=None,
                operator_id=caller.operator_id, reason=body.reason, request_id=request_id,
            )
        response.status_code = 202
        return OffboardResponse(slug=slug, applied=False, status=row["status"], request=req)
    finally:
        reg.close()


def _offboard_attested(
    slug: str, *, reason: str, attestation: str, caller: sessions.SessionInfo,
    request_id: str, background: BackgroundTasks,
) -> OffboardResponse:
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            _check_offboardable(reg, slug)
            now = utcnow_iso()
            rid = _insert_attested_record(
                reg, kind="offboard", subject=slug, target=None,
                operator_id=caller.operator_id, reason=reason, attestation=attestation,
                confirmation=slug, request_id=request_id, now=now,
            )
            mappings, access, revoked = _apply_offboard(
                reg, slug, operator_id=caller.operator_id, reason=reason,
                request_id=request_id,
                approval={"approval_mode": "single_attested", "change_request_id": rid},
            )
            title, text = _notice_text(
                reg, kind="offboard", actor_id=caller.operator_id, subject=slug, target=None,
                change_request_id=rid, reason=reason, now=now,
            )
            batch = operator_notices.notify_other_admins(
                reg, kind="single_attested_offboard", actor_id=caller.operator_id,
                subject_slug=slug, target_slug=None, change_request_id=rid, title=title,
                body=text, request_id=request_id,
            )
            _attested_marker(
                kind="offboard", operator_id=caller.operator_id, subject=slug, target=None,
                change_request_id=rid, reason=reason, request_id=request_id,
                attestation=attestation, confirmation=slug, notified=batch,
            )
    finally:
        reg.close()
    email = _queue_notice_email(
        background, batch, kind="offboard", actor_id=caller.operator_id, subject=slug,
        change_request_id=rid, request_id=request_id,
    )
    return OffboardResponse(
        slug=slug, applied=True, status="offboarded", mappings_frozen=mappings, access=access,
        signoffs_revoked=revoked,
        approval_mode="single_attested", change_request_id=rid, post_review_state="pending",
        notifications=NotificationOut(
            recipients=len(batch.notice_ids), in_app_error=batch.error, email=email,
        ),
    )


@router.get("/{slug}/merge-into/{target}/preview", response_model=MergePreviewOut)
def preview_merge(
    slug: str,
    target: str,
    response: Response,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> MergePreviewOut:
    """What merging `slug` into `target` would do, what it leaves behind,
    its caveats, and whether the single-person exception applies — the
    merge dialog shows all of it BEFORE anyone confirms. The same checks
    the merge runs (404/409/422 as it would answer). Unaudited: a preview
    is not a decision."""
    response.headers["Cache-Control"] = "no-store"
    is_super = operator_max_tier(caller.operator_id) >= ROLE_TIER["super_admin"]
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        s_row, t_row, count = _check_mergeable(reg, slug, target)
        eligibility = _single_person_merge_eligibility(
            reg, s_row, t_row, caller_id=caller.operator_id,
        )
        mappings = reg.execute(
            "SELECT COUNT(*) FROM adapter_tenant_map WHERE octo_client_slug = ?", (slug,),
        ).fetchone()[0]
        tokens = reg.execute(
            "SELECT COUNT(*) FROM client_tokens WHERE slug = ? AND revoked_at IS NULL", (slug,),
        ).fetchone()[0]
        scoped = _scoped_operator_ids(reg, slug)
        s_flags = ai_policy.canonical_flags(s_row["compliance_flags"])
        t_flags = ai_policy.canonical_flags(t_row["compliance_flags"])
        added = ai_policy.regimes_not_covered(s_flags, t_flags)
        flags_after = ai_policy.merged_flags(s_flags, t_flags)
        to_revoke = ai_policy.unrevoked_signoff_ids(reg, target) if flags_after != t_flags else []
        subject_to_revoke = ai_policy.unrevoked_signoff_ids(reg, slug)
        subject_status = s_row["status"]
    finally:
        reg.close()
    return MergePreviewOut(
        slug=slug, target=target, subject_status=subject_status, events_to_copy=count,
        left_behind={label: _count_rows(slug, db, table) for label, db, table in _LEFT_BEHIND},
        mappings_to_repoint=int(mappings), tokens_to_revoke=int(tokens),
        scoped_operators=len(scoped), target_flags_added=added, target_flags_after=flags_after,
        target_signoffs_to_revoke=to_revoke, subject_signoffs_to_revoke=subject_to_revoke,
        single_person=eligibility,
        caller_may_apply_alone=is_super,
        caveats=[CaveatOut(code=c, text=t) for c, t in MERGE_CAVEATS],
    )


@router.post("/{slug}/merge-into/{target}", response_model=MergeResponse)
def merge_tenant(
    slug: str,
    target: str,
    body: LifecycleActionRequest,
    request: Request,
    response: Response,
    background: BackgroundTasks,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> MergeResponse:
    """Never without a human's approval (product ruling), and by default
    never without TWO: a change request a super_admin other than the
    requester approves (202) — for everyone, and the only path an admin
    has. A super_admin may merge alone as the attested exception
    (approval_mode 'single_attested', 200) when the eligibility guards
    allow it; otherwise 409 SINGLE_PERSON_INELIGIBLE offers the two-person
    request instead. A deployment with one super_admin can therefore still
    clear the usual case — an untagged, auto-created duplicate."""
    request_id = str(uuid.uuid4())
    is_super = operator_max_tier(caller.operator_id) >= ROLE_TIER["super_admin"]
    if body.approval_mode == "single_attested":
        attestation = _require_attestation(body, slug, is_super=is_super, kind="merge")
        # The cheap preconditions and the eligibility guards BEFORE the
        # re-authentication prompt — nobody re-authenticates only to be told
        # this needs a second person. (Checked again under the lock below.)
        ro = connect(paths.registry_db_path(), read_only=True)
        ro.row_factory = sqlite3.Row
        try:
            s_row, t_row, _count = _check_mergeable(ro, slug, target)
            _check_no_pending_merge_requests(ro, slug, target)
            eligibility = _single_person_merge_eligibility(
                ro, s_row, t_row, caller_id=caller.operator_id,
            )
        finally:
            ro.close()
        if not eligibility.eligible:
            raise _ineligible(eligibility)
        # Outside any registry transaction: step-up writes the registry.
        require_step_up(request, caller)
        return _merge_attested(
            slug, target, reason=body.reason, attestation=attestation, caller=caller,
            request_id=request_id, background=background,
        )
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            s_row, _t_row, _count = _check_mergeable(reg, slug, target)
            if _pending_request_for(reg, target) is not None:
                raise APIError("CONFLICT", f"target tenant {target!r} has a pending change request")
            req = _create_request(
                reg, kind="merge", subject=slug, target=target,
                operator_id=caller.operator_id, reason=body.reason, request_id=request_id,
            )
        response.status_code = 202
        return MergeResponse(
            slug=slug, target=target, applied=False, status=s_row["status"], request=req,
        )
    finally:
        reg.close()


def _merge_attested(
    slug: str, target: str, *, reason: str, attestation: str,
    caller: sessions.SessionInfo, request_id: str, background: BackgroundTasks,
) -> MergeResponse:
    """Every check runs again under the write lock — the pair may have
    changed while the operator re-authenticated."""
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    copied = _CopiedEvents(target)
    try:
        with transaction(reg):
            s_row, t_row, _count = _check_mergeable(reg, slug, target)
            _check_no_pending_merge_requests(reg, slug, target)
            eligibility = _single_person_merge_eligibility(
                reg, s_row, t_row, caller_id=caller.operator_id,
            )
            if not eligibility.eligible:
                raise _ineligible(eligibility)
            now = utcnow_iso()
            rid = _insert_attested_record(
                reg, kind="merge", subject=slug, target=target,
                operator_id=caller.operator_id, reason=reason, attestation=attestation,
                confirmation=slug, request_id=request_id, now=now,
            )
            result = _apply_merge(
                reg, slug, target, operator_id=caller.operator_id, reason=reason,
                request_id=request_id, copied=copied,
                approval={"approval_mode": "single_attested", "change_request_id": rid},
            )
            title, text = _notice_text(
                reg, kind="merge", actor_id=caller.operator_id, subject=slug, target=target,
                change_request_id=rid, reason=reason, now=now,
            )
            batch = operator_notices.notify_other_admins(
                reg, kind="single_attested_merge", actor_id=caller.operator_id,
                subject_slug=slug, target_slug=target, change_request_id=rid, title=title,
                body=text, request_id=request_id,
            )
            _attested_marker(
                kind="merge", operator_id=caller.operator_id, subject=slug, target=target,
                change_request_id=rid, reason=reason, request_id=request_id,
                attestation=attestation, confirmation=slug, notified=batch,
                extra={
                    "eligibility": {
                        "subject_effective_ai_policy": eligibility.subject_effective_ai_policy,
                        "target_effective_ai_policy": eligibility.target_effective_ai_policy,
                        "subject_flags_not_on_target": eligibility.subject_flags_not_on_target,
                    },
                    "events_copied": result.events_copied,
                    "target_flags_added": result.target_flags_added,
                },
            )
    except Exception:
        _undo_merge_copy(copied, subject=slug, operator_id=caller.operator_id,
                         request_id=request_id)
        raise
    finally:
        reg.close()
    email = _queue_notice_email(
        background, batch, kind="merge", actor_id=caller.operator_id, subject=slug,
        change_request_id=rid, request_id=request_id,
    )
    return result.model_copy(update={
        "approval_mode": "single_attested", "change_request_id": rid,
        "post_review_state": "pending",
        "notifications": NotificationOut(
            recipients=len(batch.notice_ids), in_app_error=batch.error, email=email,
        ),
    })


# ---------------------------------------------------------------------------
# Change requests
# ---------------------------------------------------------------------------

@router.get("/requests", response_model=RequestListResponse)
def list_requests(
    state: str = Query(default="pending"),
    approval_mode: Optional[str] = Query(default=None),
    _caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> RequestListResponse:
    """`approval_mode=single_attested` lists the changes one super_admin
    applied alone (the requests panel's post-review list)."""
    if state not in ("pending", "approved", "rejected", "applied", "cancelled", "all"):
        raise APIError("VALIDATION_FAILED", "unknown state filter")
    if approval_mode is not None and approval_mode not in APPROVAL_MODES:
        raise APIError("VALIDATION_FAILED", "unknown approval_mode filter")
    where: list[str] = []
    args: list[Any] = []
    if state != "all":
        where.append("state = ?")
        args.append(state)
    if approval_mode is not None:
        where.append("approval_mode = ?")
        args.append(approval_mode)
    sql = "SELECT * FROM tenant_change_requests"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(ATTESTED_LIST_MAX if approval_mode == "single_attested" else 500)
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        rows = reg.execute(sql, args).fetchall()
    finally:
        reg.close()
    return RequestListResponse(requests=[_request_out(r) for r in rows])


def _require_pending(conn: sqlite3.Connection, request_db_id: int) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM tenant_change_requests WHERE id = ?", (request_db_id,),
    ).fetchone()
    if row is None:
        raise APIError("NOT_FOUND", f"no change request {request_db_id}")
    if row["state"] != "pending":
        raise APIError("CONFLICT", f"change request {request_db_id} is {row['state']}")
    return row


@router.post("/requests/{request_db_id}/approve", response_model=ChangeRequestOut)
def approve_request(
    request_db_id: int,
    body: DecisionRequest | None = None,
    caller: sessions.SessionInfo = Depends(session_super_admin),
) -> ChangeRequestOut:
    """Approving APPLIES the change. The approver must not be the requester.

    The audit chain must tell the truth: every cheap precondition runs
    BEFORE the approve row is written (a 409 leaves no trace of an
    approval), and if applying still fails after that (a store error
    mid-copy) the registry transaction rolls back AND a
    `tenant_change_request_apply_failed` row is appended — the audit DB is
    separate and cannot roll back — so a reader is never told a merge or
    offboard happened when it did not. The request stays pending. (A merge
    writes its own 'tenant_merge' row only once the copy succeeded, and a
    'tenant_merge_failed' row otherwise — see `_apply_merge`.)"""
    note = clean_line((body.note if body else None) or "", MAX_NOTE) or None
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    copied: _CopiedEvents | None = None
    row: sqlite3.Row | None = None
    try:
        with transaction(reg):
            row = _require_pending(reg, request_db_id)
            if int(row["requested_by"]) == caller.operator_id:
                raise APIError(
                    "CONFLICT",
                    "two-person rule: a change request must be approved by a "
                    "different super_admin than the one who requested it",
                )
            if row["kind"] == "offboard":
                _check_offboardable(reg, row["subject_slug"])
            else:
                _check_mergeable(reg, row["subject_slug"], row["target_slug"])
            _audit_row(
                operator_id=caller.operator_id, action="tenant_change_request_approve",
                slug=row["subject_slug"], target_kind="tenant_change_request",
                target_id=str(request_db_id),
                before={"kind": row["kind"], "state": "pending", "requested_by": row["requested_by"]},
                after={"kind": row["kind"], "state": "applied"},
                reason=note or "approved", request_id=row["request_id"],
            )
            # This row leaves 'pending' FIRST so applying (which cancels any
            # other pending request on the subject) does not touch it; the
            # transaction makes the two one change.
            reg.execute(
                "UPDATE tenant_change_requests SET state = 'applied', decided_by = ?, "
                "decided_at = ?, decision_note = ? WHERE id = ?",
                (caller.operator_id, utcnow_iso(), note, request_db_id),
            )
            apply_reason = f"approved change request {request_db_id}: {row['reason']}"
            approval = {"approval_mode": "two_person", "change_request_id": request_db_id,
                        "requested_by": int(row["requested_by"])}
            try:
                if row["kind"] == "offboard":
                    _apply_offboard(
                        reg, row["subject_slug"], operator_id=caller.operator_id,
                        reason=apply_reason, request_id=row["request_id"], approval=approval,
                    )
                else:
                    copied = _CopiedEvents(row["target_slug"])
                    _apply_merge(
                        reg, row["subject_slug"], row["target_slug"],
                        operator_id=caller.operator_id, reason=apply_reason,
                        request_id=row["request_id"], copied=copied, approval=approval,
                    )
            except Exception as exc:
                # Nothing about the failure is vendor text; the type names it.
                _audit_row(
                    operator_id=caller.operator_id,
                    action="tenant_change_request_apply_failed",
                    slug=row["subject_slug"], target_kind="tenant_change_request",
                    target_id=str(request_db_id),
                    before={"kind": row["kind"], "state": "applied"},
                    after={"kind": row["kind"], "state": "pending",
                           "error": type(exc).__name__},
                    reason="applying the approved change failed; the request stays pending",
                    request_id=row["request_id"],
                )
                raise
            return _request_out(reg.execute(
                "SELECT * FROM tenant_change_requests WHERE id = ?", (request_db_id,),
            ).fetchone())
    except Exception:
        if copied is not None and row is not None:
            _undo_merge_copy(copied, subject=row["subject_slug"], operator_id=caller.operator_id,
                             request_id=row["request_id"])
        raise
    finally:
        reg.close()


@router.post("/requests/{request_db_id}/reject", response_model=ChangeRequestOut)
def reject_request(
    request_db_id: int,
    body: DecisionRequest | None = None,
    caller: sessions.SessionInfo = Depends(session_super_admin),
) -> ChangeRequestOut:
    note = clean_line((body.note if body else None) or "", MAX_NOTE) or None
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = _require_pending(reg, request_db_id)
            if int(row["requested_by"]) == caller.operator_id:
                raise APIError(
                    "CONFLICT", "cancel your own request instead of rejecting it",
                )
            _audit_row(
                operator_id=caller.operator_id, action="tenant_change_request_reject",
                slug=row["subject_slug"], target_kind="tenant_change_request",
                target_id=str(request_db_id),
                before={"kind": row["kind"], "state": "pending"},
                after={"kind": row["kind"], "state": "rejected"},
                reason=note or "rejected", request_id=row["request_id"],
            )
            reg.execute(
                "UPDATE tenant_change_requests SET state = 'rejected', decided_by = ?, "
                "decided_at = ?, decision_note = ? WHERE id = ?",
                (caller.operator_id, utcnow_iso(), note, request_db_id),
            )
            return _request_out(reg.execute(
                "SELECT * FROM tenant_change_requests WHERE id = ?", (request_db_id,),
            ).fetchone())
    finally:
        reg.close()


@router.post("/requests/{request_db_id}/cancel", response_model=ChangeRequestOut)
def cancel_request(
    request_db_id: int,
    body: DecisionRequest | None = None,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ChangeRequestOut:
    note = clean_line((body.note if body else None) or "", MAX_NOTE) or None
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = _require_pending(reg, request_db_id)
            if int(row["requested_by"]) != caller.operator_id:
                raise APIError("ISOLATION_VIOLATION", "only the requester can cancel a request")
            _audit_row(
                operator_id=caller.operator_id, action="tenant_change_request_cancel",
                slug=row["subject_slug"], target_kind="tenant_change_request",
                target_id=str(request_db_id),
                before={"kind": row["kind"], "state": "pending"},
                after={"kind": row["kind"], "state": "cancelled"},
                reason=note or "cancelled by requester", request_id=row["request_id"],
            )
            reg.execute(
                "UPDATE tenant_change_requests SET state = 'cancelled', decided_by = ?, "
                "decided_at = ?, decision_note = ? WHERE id = ?",
                (caller.operator_id, utcnow_iso(), note, request_db_id),
            )
            return _request_out(reg.execute(
                "SELECT * FROM tenant_change_requests WHERE id = ?", (request_db_id,),
            ).fetchone())
    finally:
        reg.close()


@router.post("/requests/{request_db_id}/post-review", response_model=ChangeRequestOut)
def post_review_request(
    request_db_id: int,
    body: PostReviewRequest,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> ChangeRequestOut:
    """The optional after-the-fact review of a SINGLE-PERSON change, by a
    SECOND admin+ (never the one who applied it): reviewed_ok or
    reviewed_concern, with a note — once. Audited
    'tenant_change_request_post_review'; the reviewer's own notice about the
    change is acknowledged with it (reviewing it is having seen it)."""
    note = clean_line(body.note, MAX_NOTE)
    if len(note) < 3:
        raise APIError("VALIDATION_FAILED", "a post-review needs a note (at least 3 characters)")
    state = POST_REVIEW_VERDICTS[body.verdict]
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = reg.execute(
                "SELECT * FROM tenant_change_requests WHERE id = ?", (request_db_id,),
            ).fetchone()
            if row is None:
                raise APIError("NOT_FOUND", f"no change request {request_db_id}")
            if row["approval_mode"] != "single_attested":
                raise APIError(
                    "CONFLICT",
                    "only a change one person applied alone takes a post-review — a two-person "
                    "request was reviewed by its approver before it applied",
                )
            if row["post_review_state"] != "pending":
                raise APIError(
                    "CONFLICT",
                    f"change request {request_db_id} was already post-reviewed "
                    f"({row['post_review_state']})",
                )
            if int(row["requested_by"]) == caller.operator_id:
                raise APIError(
                    "CONFLICT",
                    "second-person rule: a single-person change is post-reviewed by an admin "
                    "other than the one who applied it",
                )
            now = utcnow_iso()
            acknowledged = [int(r[0]) for r in reg.execute(
                "SELECT id FROM operator_notices WHERE change_request_id = ? "
                "AND recipient_id = ? AND acknowledged_at IS NULL ORDER BY id",
                (request_db_id, caller.operator_id),
            ).fetchall()]
            _audit_row(
                operator_id=caller.operator_id, action="tenant_change_request_post_review",
                slug=row["subject_slug"], target_kind="tenant_change_request",
                target_id=str(request_db_id),
                before={"kind": row["kind"], "approval_mode": "single_attested",
                        "post_review_state": "pending", "applied_by": int(row["requested_by"])},
                after={"kind": row["kind"], "approval_mode": "single_attested",
                       "post_review_state": state, "verdict": body.verdict,
                       "notices_acknowledged": acknowledged},
                reason=note, request_id=row["request_id"],
            )
            reg.execute(
                "UPDATE tenant_change_requests SET post_review_state = ?, post_reviewed_by = ?, "
                "post_reviewed_at = ?, post_review_note = ? WHERE id = ?",
                (state, caller.operator_id, now, note, request_db_id),
            )
            operator_notices.acknowledge_for_change(
                reg, request_db_id, caller.operator_id, now=now,
            )
            return _request_out(reg.execute(
                "SELECT * FROM tenant_change_requests WHERE id = ?", (request_db_id,),
            ).fetchone())
    finally:
        reg.close()


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def _q_out(
    row: quarantine.QuarantineRow,
    suggestions: dict[str, tenant_autocreate.NameSuggestion] | None = None,
) -> QuarantineRowOut:
    sug = None
    if (suggestions is not None and row.state == "held"
            and row.reason in tenant_autocreate.SUGGESTION_REASONS and row.vendor_tenant_label):
        sug = suggestions.get(row.vendor_tenant_label)
    return QuarantineRowOut(
        id=row.id, received_at=row.received_at, instance_id=row.adapter_instance_id,
        vendor=row.vendor_slug, source=row.source, vendor_tenant_id=row.vendor_tenant_id,
        vendor_tenant_label=row.vendor_tenant_label, reason=row.reason,
        event_summary=row.event_summary, payload_sha256=row.payload_sha256,
        payload_truncated=row.payload_truncated, state=row.state,
        routed_to_slug=row.routed_to_slug, routed_at=row.routed_at,
        discarded_at=row.discarded_at, discard_reason=row.discard_reason,
        suggested_slug=sug.slug if sug else None,
        suggested_name=sug.display_name if sug else None,
    )


def _suggestions_for(rows: list[quarantine.QuarantineRow]) -> dict[str, tenant_autocreate.NameSuggestion]:
    """One registry read for a page: the "map to <client>" suggestion of
    every held name-match row."""
    return tenant_autocreate.name_suggestions(
        r.vendor_tenant_label for r in rows
        if r.state == "held" and r.reason in tenant_autocreate.SUGGESTION_REASONS
    )


@quarantine_router.get("", response_model=QuarantineListResponse)
def list_quarantine(
    response: Response,
    instance_id: int | None = Query(default=None),
    reason: str | None = Query(default=None),
    vendor_tenant_id: str | None = Query(default=None, max_length=256),
    state: str = Query(default="held"),
    limit: int = Query(default=50, ge=1, le=QUARANTINE_PAGE_MAX),
    offset: int = Query(default=0, ge=0),
    _caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> QuarantineListResponse:
    response.headers["Cache-Control"] = "no-store"
    if reason is not None and reason not in quarantine.REASONS:
        raise APIError("VALIDATION_FAILED", f"reason must be one of {', '.join(quarantine.REASONS)}")
    if state not in ("held", "routed", "discarded", "all"):
        raise APIError("VALIDATION_FAILED", "state must be held, routed, discarded or all")
    rows, total = quarantine.list_rows(
        instance_id=instance_id, reason=reason, vendor_tenant_id=vendor_tenant_id,
        state=state, limit=limit, offset=offset,
    )
    suggestions = _suggestions_for(rows)
    return QuarantineListResponse(
        rows=[_q_out(r, suggestions) for r in rows], total=total, limit=limit, offset=offset,
    )


@quarantine_router.get("/{row_id}", response_model=QuarantineDetailOut)
def get_quarantined(
    row_id: int,
    response: Response,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> QuarantineDetailOut:
    response.headers["Cache-Control"] = "no-store"
    row = quarantine.get(row_id)
    if row is None:
        raise APIError("NOT_FOUND", f"no quarantined event {row_id}")
    # The one quarantine read that is audited: it hands out a raw vendor
    # payload on demand (docs/audit-policy.md — drill-downs into raw
    # tenant data are one row per call). The hash names what was seen.
    _audit_row(
        operator_id=caller.operator_id, action="quarantine_fetch", slug="global",
        target_kind="quarantine", target_id=str(row.id),
        after={"instance_id": row.adapter_instance_id, "reason": row.reason,
               "state": row.state, "payload_sha256": row.payload_sha256,
               "session_id_prefix": caller.id[:8]},
        reason="held event payload viewed",
    )
    return QuarantineDetailOut(
        **_q_out(row, _suggestions_for([row])).model_dump(),
        payload=quarantine.payload_text(row_id) or "",
    )


def _validated_quarantine_reason(reason: str | None) -> str | None:
    if reason is not None and reason not in quarantine.REASONS:
        raise APIError(
            "VALIDATION_FAILED",
            f"quarantine_reason must be one of {', '.join(quarantine.REASONS)}",
        )
    return reason


def _adapter_for(request: Request, vendor_slug: str) -> Any:
    registry = getattr(request.app.state, "adapter_registry", None)
    cls = registry.get_adapter_class(vendor_slug) if registry is not None else None
    if cls is None:
        raise APIError("ADAPTER_NOT_FOUND", f"no adapter registered with slug {vendor_slug!r}")
    return cls()


def _target_for_route(
    body: RouteRequest, *, caller: sessions.SessionInfo, request_id: str,
) -> tuple[str, bool]:
    """The tenant a held event goes to: an existing active one, or a new one
    created here (audited). Returns (slug, created)."""
    if bool(body.slug) == bool(body.new):
        raise APIError("VALIDATION_FAILED", "give either an existing 'slug' or a 'new' tenant")
    if body.slug:
        reg = connect(paths.registry_db_path(), read_only=True)
        reg.row_factory = sqlite3.Row
        try:
            row = _require_tenant(reg, body.slug)
        finally:
            reg.close()
        if row["status"] != "active":
            raise APIError("CONFLICT", f"tenant {body.slug!r} is {row['status']}")
        return body.slug, False
    spec = body.new
    assert spec is not None
    kind = _validated_kind(spec.kind)
    flags = _validated_flags(spec.compliance_flags)
    display_name = " ".join(spec.display_name.split())
    reg = connect(paths.registry_db_path(), read_only=True)
    try:
        slug = tenant_autocreate.free_slug(
            reg, tenant_autocreate.slug_from_name(display_name),
        )
    finally:
        reg.close()
    create_manual_tenant(
        slug, display_name, kind=kind, flags=flags, ai_policy="none",
        operator_id=caller.operator_id,
        reason="tenant created while routing quarantined traffic", request_id=request_id,
    )
    return slug, True


def _replay_source(request: Request, row: quarantine.QuarantineRow) -> tuple[Any, dict[str, Any]]:
    """The adapter and the envelope a held row replays through — resolved
    BEFORE any tenant is created for it, so a payload that cannot be
    replayed (truncated on arrival, not a JSON object) or a vendor whose
    adapter is not registered never leaves an orphan tenant behind."""
    envelope = quarantine.payload_json(row.id)
    if envelope is None:
        raise APIError(
            "CONFLICT",
            f"quarantined event {row.id} cannot be replayed (payload truncated or not "
            "a JSON object) — discard it",
        )
    return _adapter_for(request, row.vendor_slug), envelope


def _write_mapping(
    *, instance_id: int, vendor_tenant_id: str, slug: str, label: str | None,
    operator_id: int, request_id: str,
) -> bool:
    """Map the vendor site to `slug` (match_source 'manual') so its future
    traffic routes there. A disabled instance gets no mapping (it has no
    future traffic). Audited with before/after. True when written."""
    rec = get_instance(instance_id)
    if rec is None or rec.disabled_at is not None:
        return False
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            before = reg.execute(
                "SELECT octo_client_slug, match_source FROM adapter_tenant_map "
                "WHERE adapter_instance_id = ? AND vendor_tenant_id = ?",
                (instance_id, vendor_tenant_id),
            ).fetchone()
            if before is not None and before["octo_client_slug"] == slug:
                return False
            _audit_row(
                operator_id=operator_id, action="adapter_tenant_map_set", slug=slug,
                target_kind="adapter_instance", target_id=str(instance_id),
                before={"vendor_tenant_id": vendor_tenant_id,
                        "octo_client_slug": before["octo_client_slug"] if before else None},
                after={"vendor_tenant_id": vendor_tenant_id, "octo_client_slug": slug,
                       "match_source": "manual"},
                reason="mapping set while routing quarantined traffic", request_id=request_id,
            )
            reg.execute(
                "INSERT INTO adapter_tenant_map (adapter_instance_id, vendor_tenant_id, "
                " octo_client_slug, vendor_tenant_label, match_source, updated_at, "
                " updated_by_operator_id) VALUES (?, ?, ?, ?, 'manual', ?, ?) "
                "ON CONFLICT(adapter_instance_id, vendor_tenant_id) DO UPDATE SET "
                " octo_client_slug = excluded.octo_client_slug, "
                " vendor_tenant_label = COALESCE(excluded.vendor_tenant_label, vendor_tenant_label), "
                " match_source = 'manual', updated_at = excluded.updated_at, "
                " updated_by_operator_id = excluded.updated_by_operator_id",
                (instance_id, vendor_tenant_id, slug,
                 (label or "")[:MAX_LABEL_CHARS] or None, utcnow_iso(), operator_id),
            )
    finally:
        reg.close()
    return True


def _ingest_held(
    row: quarantine.QuarantineRow, adapter: Any, envelope: dict[str, Any], slug: str, *,
    operator_id: int, request_id: str,
) -> tuple[bool, bool]:
    """Re-ingest one held payload into `slug` through the adapter's own
    extract path (same event_type / headline as live traffic), then mark it
    routed. Returns (routed, duplicate)."""
    event = adapter.extract_event(envelope)
    try:
        outcome = SqliteIngestSink().ingest(slug, row.vendor_slug, event)
    except FileNotFoundError:
        raise APIError("CONFLICT", f"tenant {slug!r} has no events store")
    duplicate = bool(getattr(outcome, "duplicate", False))
    _audit_row(
        operator_id=operator_id, action="quarantine_route", slug=slug,
        target_kind="quarantine", target_id=str(row.id),
        before={"reason": row.reason, "vendor_tenant_id": row.vendor_tenant_id,
                "instance_id": row.adapter_instance_id},
        after={"routed_to_slug": slug, "event_id": getattr(outcome, "event_id", None),
               "duplicate": duplicate},
        reason="quarantined event routed by operator", request_id=request_id,
    )
    routed = quarantine.mark_routed(row.id, slug=slug, by=str(operator_id))
    return routed, duplicate


@quarantine_router.post("/{row_id}/route", response_model=RouteResponse)
def route_quarantined(
    row_id: int,
    body: RouteRequest,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> RouteResponse:
    row = quarantine.get(row_id)
    if row is None:
        raise APIError("NOT_FOUND", f"no quarantined event {row_id}")
    if row.state != "held":
        raise APIError("CONFLICT", f"quarantined event {row_id} is already {row.state}")
    request_id = str(uuid.uuid4())
    adapter, envelope = _replay_source(request, row)      # before anything is created
    slug, created = _target_for_route(body, caller=caller, request_id=request_id)
    routed, duplicate = _ingest_held(
        row, adapter, envelope, slug, operator_id=caller.operator_id, request_id=request_id,
    )
    mapped = False
    if row.vendor_tenant_id:
        mapped = _write_mapping(
            instance_id=row.adapter_instance_id, vendor_tenant_id=row.vendor_tenant_id,
            slug=slug, label=row.vendor_tenant_label, operator_id=caller.operator_id,
            request_id=request_id,
        )
    return RouteResponse(
        slug=slug, created_tenant=created, routed=1 if routed else 0,
        duplicates=1 if duplicate else 0, mapping_written=mapped,
    )


@quarantine_router.post("/bulk-route", response_model=RouteResponse)
def bulk_route_quarantined(
    body: BulkRouteRequest,
    request: Request,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> RouteResponse:
    """Every held event from one vendor site on one instance → one tenant,
    and the site mapped once. Bounded per call. A payload that cannot be
    replayed (truncated on arrival) is skipped and counted, never a reason
    to stop half-way: the operator decided where the SITE belongs, so the
    rest is routed and the mapping written regardless. Nothing is created
    unless at least one event can be replayed."""
    reason = _validated_quarantine_reason(body.quarantine_reason)
    all_ids = quarantine.held_ids_for_vendor_tenant(
        body.instance_id, body.vendor_tenant_id, reason=reason,
    )
    if not all_ids:
        raise APIError("NOT_FOUND", "no held events for that vendor tenant on that instance")
    ids = quarantine.held_ids_for_vendor_tenant(
        body.instance_id, body.vendor_tenant_id, reason=reason, replayable_only=True,
    )
    skipped = len(all_ids) - len(ids)
    if not ids:
        raise APIError(
            "CONFLICT",
            f"none of the {skipped} held event(s) can be replayed (payloads truncated "
            "on arrival) — discard them",
        )
    request_id = str(uuid.uuid4())
    routed = duplicates = 0
    label: str | None = None
    slug: str | None = None
    created = False
    for row_id in ids[:BULK_ROUTE_MAX]:
        row = quarantine.get(row_id)
        if row is None or row.state != "held":
            continue
        try:
            adapter, envelope = _replay_source(request, row)
        except APIError as exc:
            if exc.code != "CONFLICT":
                raise                                      # no adapter: nothing to do
            skipped += 1                                   # not an object after all
            continue
        if slug is None:                                   # first replayable row
            slug, created = _target_for_route(body, caller=caller, request_id=request_id)
        label = label or row.vendor_tenant_label
        ok, dup = _ingest_held(
            row, adapter, envelope, slug, operator_id=caller.operator_id,
            request_id=request_id,
        )
        routed += 1 if ok else 0
        duplicates += 1 if dup else 0
    if slug is None:
        raise APIError("CONFLICT", "none of the held events can be replayed — discard them")
    mapped = _write_mapping(
        instance_id=body.instance_id, vendor_tenant_id=body.vendor_tenant_id, slug=slug,
        label=label, operator_id=caller.operator_id, request_id=request_id,
    )
    return RouteResponse(
        slug=slug, created_tenant=created, routed=routed, duplicates=duplicates,
        skipped=skipped, mapping_written=mapped,
    )


def _discard_held(
    row: quarantine.QuarantineRow, *, operator_id: int, reason: str,
    request_id: str | None = None,
) -> bool:
    """Audit, then discard one held row. True when it was held and is now
    discarded."""
    _audit_row(
        operator_id=operator_id, action="quarantine_discard", slug="global",
        target_kind="quarantine", target_id=str(row.id),
        before={"reason": row.reason, "vendor_tenant_id": row.vendor_tenant_id,
                "instance_id": row.adapter_instance_id},
        after={"discarded": True},
        reason=reason, request_id=request_id,
    )
    return quarantine.mark_discarded(row.id, by=str(operator_id), reason=reason)


@quarantine_router.post("/{row_id}/discard", response_model=DiscardResponse)
def discard_quarantined(
    row_id: int,
    body: ReasonRequest,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> DiscardResponse:
    row = quarantine.get(row_id)
    if row is None:
        raise APIError("NOT_FOUND", f"no quarantined event {row_id}")
    if row.state != "held":
        raise APIError("CONFLICT", f"quarantined event {row_id} is already {row.state}")
    done = _discard_held(row, operator_id=caller.operator_id, reason=body.reason)
    return DiscardResponse(id=row_id, discarded=done)


@quarantine_router.post("/bulk-discard", response_model=BulkDiscardResponse)
def bulk_discard_quarantined(
    body: BulkDiscardRequest,
    caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> BulkDiscardResponse:
    """Every held event from one vendor site on one instance (optionally
    one hold reason) discarded with one operator reason — the console's
    "Discard all" on a group. One audit row per event, like routing; no
    mapping is written (nothing was decided about the site's future
    traffic). Bounded per call."""
    ids = quarantine.held_ids_for_vendor_tenant(
        body.instance_id, body.vendor_tenant_id,
        reason=_validated_quarantine_reason(body.quarantine_reason),
    )
    if not ids:
        raise APIError("NOT_FOUND", "no held events for that vendor tenant on that instance")
    request_id = str(uuid.uuid4())
    discarded = 0
    for row_id in ids[:BULK_ROUTE_MAX]:
        row = quarantine.get(row_id)
        if row is None or row.state != "held":
            continue
        if _discard_held(
            row, operator_id=caller.operator_id, reason=body.reason, request_id=request_id,
        ):
            discarded += 1
    return BulkDiscardResponse(discarded=discarded)


# JSON helpers used by tests / other routers.
def tenant_row_json(slug: str) -> dict[str, Any] | None:
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        row = _tenant_row(reg, slug)
        return json.loads(_tenant_out(reg, row, _instance_index()).model_dump_json()) if row else None
    finally:
        reg.close()
