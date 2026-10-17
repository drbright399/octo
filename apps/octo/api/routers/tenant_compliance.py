"""Compliance sign-off before cloud AI — `/api/v1/admin/tenants/{slug}/…`.

A tenant may ASK for `ai_policy = 'cloud'` (a super_admin sets it, as
before), but cloud is honoured only while an Athena Admin (super_admin) has
signed for EXACTLY the tenant's current compliance flags, naming the
agreement each of those regimes requires (`instances.ai_policy`). These
routes record, revoke and show those sign-offs:

  GET  /admin/tenants/{slug}/compliance-signoffs
        admin+. The tenant's AI policy (requested vs effective, and why), its
        sign-off history newest first (revoked and expired rows included),
        and the attestation template the sign-off dialog shows. Unaudited —
        a read is not a decision (docs/audit-policy.md).
  POST /admin/tenants/{slug}/compliance-signoff
        super_admin + step-up. {agreement_references, attestation_text,
        attestation_version, acknowledge_flags, term_months?}.
        `agreement_references` names ONE agreement per regime in the flags
        ({"hipaa": "<BAA ref>", "cjis": "<CJIS Security Addendum ref>"}; a
        never-tagged tenant: {"untagged": "<data-processing agreement>"}) —
        the history shows which instrument each regime needs
        (`agreements_required`). The
        acknowledged flags must EQUAL the tenant's current flags — a dialog
        opened before someone changed them cannot sign the stale set (409).
        Stored flags that are not a list of known tags cannot be signed for
        (409 — re-tag the tenant first).
        The attestation version must be the current template's (409 when the
        wording changed under the dialog). Stores the exact typed text, its
        sha256 and the template version; supersedes any earlier unrevoked
        sign-off; audited 'tenant_compliance_signoff'. A tenant tagged
        exactly ["none"] needs no sign-off (409); '[]' (never tagged) does.
  POST /admin/tenants/{slug}/compliance-signoff/{id}/revoke
        super_admin + step-up. {reason}. Audited
        'tenant_compliance_signoff_revoke'. A 'cloud' tenant runs as 'local'
        from the next model call on.

Step-up is the search surface's own `require_step_up` (password + TOTP,
IP-bound window) — the same second gate the model-swap routes use. Every
write is one registry transaction whose audit row is appended inside it: an
audit failure rolls the write back, so nothing changes unaudited. Audit rows
carry the attestation's sha256 and version, never the typed text (it lives
in the append-only table the hash pins).
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_admin_plus, session_super_admin
from apps.octo.api.routers.admin_tenants import (
    SignoffStatusOut,
    _audit_row,
    _require_tenant,
    signoff_status_out,
)
from apps.octo.api.routers.search import require_step_up
from apps.octo.auth import sessions
from apps.octo.db import connect, transaction
from apps.octo.ingest.presentation import clean_line
from apps.octo.instances import ai_policy
from apps.octo.instances.tenant_lifecycle import COMPLIANCE_TAGS, validate_compliance_flags

router = APIRouter(prefix="/admin/tenants", tags=["admin-tenants", "compliance"])


def _super_admin_step_up():
    """super_admin FIRST (an admin gets 403, not a re-auth prompt), then an
    active step-up window — both on the same session."""

    def _dep(
        _role: sessions.SessionInfo = Depends(session_super_admin),
        info: sessions.SessionInfo = Depends(require_step_up),
    ) -> sessions.SessionInfo:
        return info

    _dep.__name__ = "session_super_admin_with_step_up"
    return _dep


session_super_admin_step_up = _super_admin_step_up()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AiPolicyOut(BaseModel):
    requested: str
    effective: str
    degraded: bool
    reason: str | None = None
    flags: list[str] = Field(default_factory=list)
    signoff: SignoffStatusOut


class SignoffOut(BaseModel):
    id: int
    slug: str
    policy: str
    flags_covered: list[str]
    # {regime: reference} — one agreement per regime covered ('untagged' for
    # a never-tagged tenant; 'reference' for a pre-v2 single reference).
    agreement_references: dict[str, str]
    attestation_text: str
    attestation_sha256: str
    attestation_version: str
    signed_by: int
    signed_at: str
    expires_at: str | None = None
    revoked_at: str | None = None
    revoked_by: int | None = None
    revoked_kind: str | None = None
    revoke_reason: str | None = None
    # live | expired | revoked | superseded | flags_changed (relative to the
    # tenant's flags NOW) — per row, for the history view.
    state: str


class AttestationTemplateOut(BaseModel):
    version: str
    text: str
    min_chars: int = ai_policy.ATTESTATION_MIN_CHARS
    max_chars: int = ai_policy.ATTESTATION_MAX_CHARS


class AgreementRequiredOut(BaseModel):
    key: str            # a regime, or 'untagged'
    instrument: str     # what that regime's agreement is


class SignoffHistoryResponse(BaseModel):
    slug: str
    display_name: str
    status: str
    ai_policy: AiPolicyOut
    signoffs: list[SignoffOut]
    attestation: AttestationTemplateOut
    # The agreements a sign-off for the tenant's CURRENT flags must name.
    agreements_required: list[AgreementRequiredOut]
    term_months_default: int = ai_policy.SIGNOFF_TERM_MONTHS_DEFAULT
    term_months_max: int = ai_policy.SIGNOFF_TERM_MONTHS_MAX
    agreement_reference_max_chars: int = ai_policy.AGREEMENT_REFERENCE_MAX_CHARS


class SignoffRequest(BaseModel):
    agreement_references: dict[str, str] = Field(
        min_length=1, max_length=len(ai_policy.AGREEMENT_INSTRUMENTS),
    )
    attestation_text: str = Field(
        min_length=ai_policy.ATTESTATION_MIN_CHARS, max_length=ai_policy.ATTESTATION_MAX_CHARS,
    )
    attestation_version: str = Field(min_length=1, max_length=64)
    # Must equal the tenant's current flags — what the signer was shown.
    acknowledge_flags: list[str] = Field(max_length=len(COMPLIANCE_TAGS))
    term_months: int = Field(
        default=ai_policy.SIGNOFF_TERM_MONTHS_DEFAULT, ge=1, le=ai_policy.SIGNOFF_TERM_MONTHS_MAX,
    )


class RevokeSignoffRequest(BaseModel):
    reason: str = Field(
        min_length=ai_policy.REVOKE_REASON_MIN_CHARS, max_length=ai_policy.REVOKE_REASON_MAX_CHARS,
    )


class SignoffResultOut(BaseModel):
    slug: str
    signoff: SignoffOut
    ai_policy: AiPolicyOut
    # Earlier unrevoked sign-offs this one replaced (signing only).
    superseded: list[int] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _policy_out(status: ai_policy.AiPolicyStatus) -> AiPolicyOut:
    return AiPolicyOut(
        requested=status.requested, effective=status.effective, degraded=status.degraded,
        reason=status.reason, flags=list(status.flags),
        signoff=signoff_status_out(status.signoff),
    )


def _row_state(r: dict[str, Any], status: ai_policy.AiPolicyStatus) -> str:
    """One history row's standing against the tenant as it is now."""
    if r["revoked_at"] is not None:
        return {"superseded": "superseded", "flags_changed": "flags_changed",
                "merge_added_flags": "flags_changed"}.get(r["revoked_kind"], "revoked")
    if status.signoff.state == "live" and status.signoff.signoff_id == r["id"]:
        return "live"
    if ai_policy.canonical_flags(r["flags_covered"]) != list(status.flags):
        return "flags_changed"
    if ai_policy.signoff_required(status.flags):
        return "expired"
    # Tagged 'none' now: the row is neither needed nor lapsed.
    return "flags_changed"


def _signoff_out(r: dict[str, Any], status: ai_policy.AiPolicyStatus) -> SignoffOut:
    return SignoffOut(
        id=int(r["id"]), slug=r["slug"], policy=r["policy"],
        flags_covered=ai_policy.canonical_flags(r["flags_covered"]),
        agreement_references=ai_policy.parse_agreement_references(r["baa_reference"]),
        attestation_text=r["attestation_text"],
        attestation_sha256=r["attestation_sha256"],
        attestation_version=r["attestation_version"], signed_by=int(r["signed_by"]),
        signed_at=r["signed_at"], expires_at=r["expires_at"], revoked_at=r["revoked_at"],
        revoked_by=r["revoked_by"], revoked_kind=r["revoked_kind"],
        revoke_reason=r["revoke_reason"], state=_row_state(r, status),
    )


def _signoff_row(conn: sqlite3.Connection, slug: str, signoff_id: int) -> dict[str, Any]:
    cur = conn.execute(
        "SELECT * FROM tenant_compliance_signoffs WHERE id = ? AND slug = ?", (signoff_id, slug),
    )
    found = cur.fetchone()
    if found is None:
        raise APIError("NOT_FOUND", f"no compliance sign-off {signoff_id} for tenant {slug!r}")
    return dict(zip([d[0] for d in cur.description], found))


def _agreements_required(flags: list[str]) -> list[AgreementRequiredOut]:
    return [
        AgreementRequiredOut(key=k, instrument=ai_policy.AGREEMENT_INSTRUMENTS[k])
        for k in ai_policy.agreement_keys(flags)
    ]


def _clean_agreements(refs: dict[str, str], flags: list[str]) -> dict[str, str]:
    """One reference per agreement the flags need — no more, no fewer —
    each a printable line of 1–AGREEMENT_REFERENCE_MAX_CHARS characters."""
    needed = ai_policy.agreement_keys(flags)
    named = ", ".join(f"{k} ({ai_policy.AGREEMENT_INSTRUMENTS[k]})" for k in needed)
    if sorted(refs) != needed:
        raise APIError(
            "VALIDATION_FAILED",
            f"name one agreement for each of: {named} — a single agreement does not cover "
            "every regime",
        )
    out: dict[str, str] = {}
    for key in needed:
        raw = refs[key]
        line = clean_line(raw, ai_policy.AGREEMENT_REFERENCE_MAX_CHARS)
        if not line or len(raw.strip()) > ai_policy.AGREEMENT_REFERENCE_MAX_CHARS:
            raise APIError(
                "VALIDATION_FAILED",
                f"the {ai_policy.AGREEMENT_INSTRUMENTS[key]} reference must be 1–"
                f"{ai_policy.AGREEMENT_REFERENCE_MAX_CHARS} characters of plain text",
            )
        out[key] = line
    return out


def _clean_attestation(text: str) -> str:
    """The typed attestation, EXACTLY as typed (it is hashed as stored), once
    it is checked: long enough without its padding, and no control
    characters beyond line breaks and tabs."""
    if len(text.strip()) < ai_policy.ATTESTATION_MIN_CHARS:
        raise APIError(
            "VALIDATION_FAILED",
            f"type the attestation — at least {ai_policy.ATTESTATION_MIN_CHARS} characters",
        )
    if any(not (c.isprintable() or c in "\n\r\t") for c in text):
        raise APIError("VALIDATION_FAILED", "the attestation must be plain text")
    return text


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/{slug}/compliance-signoffs", response_model=SignoffHistoryResponse)
def list_compliance_signoffs(
    slug: str,
    response: Response,
    _caller: sessions.SessionInfo = Depends(session_admin_plus),
) -> SignoffHistoryResponse:
    response.headers["Cache-Control"] = "no-store"
    reg = connect(paths.registry_db_path(), read_only=True)
    reg.row_factory = sqlite3.Row
    try:
        row = _require_tenant(reg, slug)
        status = ai_policy.status_for_row(reg, row)
        history = ai_policy.list_signoffs(reg, slug)
    finally:
        reg.close()
    return SignoffHistoryResponse(
        slug=slug, display_name=row["display_name"], status=row["status"],
        ai_policy=_policy_out(status),
        signoffs=[_signoff_out(dict(r), status) for r in history],
        attestation=AttestationTemplateOut(
            version=ai_policy.ATTESTATION_VERSION,
            text=ai_policy.ATTESTATION_TEMPLATES[ai_policy.ATTESTATION_VERSION],
        ),
        agreements_required=_agreements_required(list(status.flags)),
    )


@router.post("/{slug}/compliance-signoff", response_model=SignoffResultOut, status_code=201)
def sign_compliance(
    slug: str,
    body: SignoffRequest,
    caller: sessions.SessionInfo = Depends(session_super_admin_step_up),
) -> SignoffResultOut:
    text = _clean_attestation(body.attestation_text)
    if body.attestation_version not in ai_policy.ATTESTATION_TEMPLATES:
        raise APIError("VALIDATION_FAILED", "unknown attestation version")
    if body.attestation_version != ai_policy.ATTESTATION_VERSION:
        raise APIError(
            "CONFLICT",
            "the attestation wording changed since this dialog opened — reopen it, "
            "read the current text, and sign again",
        )
    try:
        acknowledged = validate_compliance_flags(body.acknowledge_flags)
    except ValueError as exc:
        raise APIError("VALIDATION_FAILED", str(exc))
    request_id = str(uuid.uuid4())
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = _require_tenant(reg, slug)
            if row["status"] in ai_policy.RETIRED_STATUSES:
                raise APIError("CONFLICT", f"tenant {slug!r} is {row['status']}")
            if not ai_policy.flags_readable(row["compliance_flags"]):
                raise APIError(
                    "CONFLICT",
                    f"tenant {slug!r} has stored compliance flags that are not a list of known "
                    "tags — re-tag it under Edit first, then sign off for what you set",
                )
            flags = ai_policy.canonical_flags(row["compliance_flags"])
            if acknowledged != flags:
                raise APIError(
                    "CONFLICT",
                    f"tenant {slug!r} is tagged {ai_policy.flags_label(flags)}, not "
                    f"{ai_policy.flags_label(acknowledged)} — its flags changed since the "
                    "dialog opened; review them and sign again",
                )
            if not ai_policy.signoff_required(flags):
                raise APIError(
                    "CONFLICT",
                    f"tenant {slug!r} is tagged 'none' (no compliance regime applies): "
                    "cloud AI needs no sign-off",
                )
            agreements = _clean_agreements(body.agreement_references, flags)
            before = ai_policy.status_for_row(reg, row)
            signoff_id, superseded = ai_policy.record_signoff(
                reg, slug, flags=flags, agreement_references=agreements, attestation_text=text,
                attestation_version=body.attestation_version, operator_id=caller.operator_id,
                request_id=request_id, term_months=body.term_months,
            )
            after = ai_policy.status_for_row(reg, row)
            stored = _signoff_row(reg, slug, signoff_id)
            _audit_row(
                operator_id=caller.operator_id, action="tenant_compliance_signoff", slug=slug,
                target_kind="tenant_compliance_signoff", target_id=str(signoff_id),
                before=ai_policy.status_json(before),
                after={
                    **(ai_policy.status_json(after) or {}),
                    "signoff_id": signoff_id, "policy": "cloud",
                    "flags_covered": flags, "agreement_references": agreements,
                    "attestation_version": body.attestation_version,
                    "attestation_sha256": stored["attestation_sha256"],
                    "attestation_chars": len(text),
                    "expires_at": stored["expires_at"], "superseded": superseded,
                },
                reason=f"compliance sign-off for cloud AI covering {ai_policy.flags_label(flags)}",
                request_id=request_id,
            )
        return SignoffResultOut(
            slug=slug, signoff=_signoff_out(stored, after), ai_policy=_policy_out(after),
            superseded=superseded,
        )
    finally:
        reg.close()


@router.post(
    "/{slug}/compliance-signoff/{signoff_id}/revoke", response_model=SignoffResultOut,
)
def revoke_compliance_signoff(
    slug: str,
    signoff_id: int,
    body: RevokeSignoffRequest,
    caller: sessions.SessionInfo = Depends(session_super_admin_step_up),
) -> SignoffResultOut:
    reason = clean_line(body.reason, ai_policy.REVOKE_REASON_MAX_CHARS)
    if len(reason) < ai_policy.REVOKE_REASON_MIN_CHARS:
        raise APIError("VALIDATION_FAILED", "say why the sign-off is revoked")
    request_id = str(uuid.uuid4())
    reg = connect(paths.registry_db_path())
    reg.row_factory = sqlite3.Row
    try:
        with transaction(reg):
            row = _require_tenant(reg, slug)
            current = _signoff_row(reg, slug, signoff_id)
            if current["revoked_at"] is not None:
                raise APIError("CONFLICT", f"compliance sign-off {signoff_id} is already revoked")
            before = ai_policy.status_for_row(reg, row)
            ai_policy.revoke_signoff(
                reg, signoff_id, operator_id=caller.operator_id, reason=reason,
            )
            after = ai_policy.status_for_row(reg, row)
            stored = _signoff_row(reg, slug, signoff_id)
            _audit_row(
                operator_id=caller.operator_id, action="tenant_compliance_signoff_revoke",
                slug=slug, target_kind="tenant_compliance_signoff", target_id=str(signoff_id),
                before={**(ai_policy.status_json(before) or {}), "signoff_id": signoff_id},
                after={**(ai_policy.status_json(after) or {}), "signoff_id": signoff_id,
                       "revoked_kind": "operator"},
                reason=reason, request_id=request_id,
            )
        return SignoffResultOut(
            slug=slug, signoff=_signoff_out(stored, after), ai_policy=_policy_out(after),
        )
    finally:
        reg.close()
