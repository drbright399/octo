"""Known-benign rules — the operator-editable list that DOWNGRADES specific
blocked domains for specific reasons (`instances.known_benign`; registry
`known_benign_rules`, migration 040). It never allowlists: the vendor keeps
blocking, Athena files the alert at the rule's level with its label.

  GET    /api/v1/admin/known-benign              analyst+ (read)
  POST   /api/v1/admin/known-benign              admin+, audited (a new rule)
  PUT    /api/v1/admin/known-benign/{id}         admin+, audited (edit / disable)

A rule is never deleted (disable it: an alert it downgraded keeps naming it).
Every write carries a reason; patterns are validated (a restricted, linear-
time regex) before they are stored.
"""
from __future__ import annotations

import json
import uuid
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Path, Response
from pydantic import BaseModel, ConfigDict, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.role_gates import session_at_least
from apps.octo.auth import audit, sessions
from apps.octo.db import connect, transaction
from apps.octo.instances import known_benign as kb

router = APIRouter(prefix="/admin/known-benign", tags=["admin"])

session_analyst_plus = session_at_least("analyst")
session_admin_plus = session_at_least("admin")


class RuleOut(BaseModel):
    id: int
    vendor: str
    match_kind: str
    pattern: str
    reasons: list[str]
    level: str
    label: str
    note: str
    enabled: bool


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vendor: Literal["nextdns"] = "nextdns"
    match_kind: Literal["exact", "suffix", "regex"]
    pattern: str = Field(min_length=1, max_length=200)
    reasons: list[str] = Field(min_length=1, max_length=10)
    level: Literal["low", "medium"] = "low"
    label: str = Field(min_length=3, max_length=120)
    note: str = Field(default="", max_length=1000)
    enabled: bool = True
    reason: str = Field(min_length=3, max_length=500)


def _rules() -> list[RuleOut]:
    return [RuleOut(**r.as_dict()) for r in kb.load(fresh=True)]


def _audit(caller: sessions.SessionInfo, action: str, target: str, before: object,
           after: object, reason: str) -> None:
    g = connect(paths.global_audit_db_path())
    try:
        audit.append(g, audit.AuditEntry(
            actor=str(caller.operator_id), actor_kind="human", action=action,
            target_kind="known_benign_rule", target_id=target, client_slug="global",
            before_state=before, after_state=after, reason=reason,
            request_id=str(uuid.uuid4())))
    finally:
        g.close()


def _validated(body: RuleIn) -> tuple[str, list[str]]:
    try:
        pattern = kb.validate_pattern(body.match_kind, body.pattern)
    except kb.RuleError as exc:
        raise APIError("VALIDATION_FAILED", str(exc)) from None
    reasons = sorted({r.strip().lower() for r in body.reasons if r.strip()})
    if not reasons or any(len(r) > 64 or not r.replace("-", "").replace(":", "").isalnum()
                          for r in reasons):
        raise APIError("VALIDATION_FAILED", "reasons are NextDNS reason ids "
                       "(e.g. threat-intelligence-feeds)")
    return pattern, reasons


@router.get("", response_model=list[RuleOut])
def list_rules(response: Response,
               caller: sessions.SessionInfo = Depends(session_analyst_plus)) -> list[RuleOut]:
    response.headers["Cache-Control"] = "no-store"
    return _rules()


@router.post("", response_model=list[RuleOut])
def create_rule(body: RuleIn,
                caller: sessions.SessionInfo = Depends(session_admin_plus)) -> list[RuleOut]:
    pattern, reasons = _validated(body)
    after = {"vendor": body.vendor, "match_kind": body.match_kind, "pattern": pattern,
             "reasons": reasons, "level": body.level, "label": body.label,
             "enabled": body.enabled}
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute(
                "INSERT INTO known_benign_rules (vendor, match_kind, pattern, reasons, level, "
                " label, note, enabled, created_by, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "
                " ?, ?)", (body.vendor, body.match_kind, pattern, json.dumps(reasons), body.level,
                           body.label, body.note, 1 if body.enabled else 0, caller.operator_id,
                           caller.operator_id))
            rule_id = int(cur.lastrowid)
    finally:
        reg.close()
    _audit(caller, "known_benign_rule_create", str(rule_id), None, after, body.reason)
    kb.reset()
    return _rules()


@router.put("/{rule_id}", response_model=list[RuleOut])
def update_rule(body: RuleIn, rule_id: int = Path(..., ge=1),
                caller: sessions.SessionInfo = Depends(session_admin_plus)) -> list[RuleOut]:
    pattern, reasons = _validated(body)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            row = reg.execute("SELECT * FROM known_benign_rules WHERE id = ?",
                              (rule_id,)).fetchone()
            if row is None:
                raise APIError("NOT_FOUND", "no such rule")
            before = {k: row[k] for k in ("match_kind", "pattern", "reasons", "level", "label",
                                          "enabled")}
            reg.execute(
                "UPDATE known_benign_rules SET match_kind = ?, pattern = ?, reasons = ?, "
                " level = ?, label = ?, note = ?, enabled = ?, updated_by = ?, "
                " updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?",
                (body.match_kind, pattern, json.dumps(reasons), body.level, body.label,
                 body.note, 1 if body.enabled else 0, caller.operator_id, rule_id))
    finally:
        reg.close()
    _audit(caller, "known_benign_rule_update", str(rule_id), before,
           {"match_kind": body.match_kind, "pattern": pattern, "reasons": reasons,
            "level": body.level, "label": body.label, "enabled": body.enabled}, body.reason)
    kb.reset()
    return _rules()


def rule_for(rule_id: int) -> Optional[RuleOut]:
    return next((r for r in _rules() if r.id == rule_id), None)
