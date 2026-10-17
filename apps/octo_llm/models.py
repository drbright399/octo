"""Pydantic request/response models for the octo-llm API.

Every endpoint's input and output is shaped by one of these models.
The structured-only contract from §11.1 v2 is enforced here: no
endpoint accepts a freeform `prompt` or `messages` field, and no
endpoint returns text outside the documented response fields.

Field-length bounds keep an attacker-controlled call from
overwhelming the prompt buffer or generating an unbounded response.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------

# Tight upper bounds on free-text fields. The LLM gets a constrained
# input surface regardless of how the caller built the payload.
MAX_NOTE_TEXT = 2048
MAX_SUMMARY_TEXT = 2048
MAX_SIGNAL_TEXT = 256
MAX_PEER_SUMMARY_TEXT = 512


# What the API can record as the originating agent identity (mirrors
# the per-tenant agent_notes.agent_id CHECK constraint).
AgentId = Literal["octo", "athena"]

# Severity buckets — match per-tenant events.severity CHECK constraint.
Severity = Literal["info", "low", "medium", "high", "critical"]

# Triage disposition — the autonomous-triage taxonomy per the
# octo-llm triage-taxonomy design decision (banked 2026-05-21):
#   - noise:     auto-suppress + round-trip closure upstream
#   - pattern:   recognized pattern; flag inline, don't bump severity
#   - escalate:  severity bump + auto-create ticket
#   - uncertain: analyst review; agent takes no autonomous action
Disposition = Literal["noise", "pattern", "escalate", "uncertain"]

# Per-call query kind — selects which prompt template the backend
# uses internally. Operator-triggered "ask octo" drawer buttons map
# to the non-default values. Default `auto_enrich` is what background
# autonomous enrichment uses.
#
# CRITICAL: this is a CLOSED enum. The model NEVER receives a
# freeform `prompt` field; query_kind selects a server-side template.
# If a caller passes an unknown kind, the request rejects with 400.
# That preserves the §11.1 v2 structured-input contract — no
# free-text path from caller to the model.
QueryKind = Literal[
    "auto_enrich",
    "tell_me_more",
    "recognized_patterns",
    "compare_recent",
    "suggest_disposition",
    "suggest_next_steps",
]


# ---------------------------------------------------------------------------
# /v1/healthz
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Liveness + model-readiness snapshot. Probed by octo-core to
    decide whether to attempt enrichment calls."""
    ok: bool
    backend: str                  # "stub" | "llama-cpp" | future backends
    model_loaded: bool
    model_version: str            # "stub-v0" in slice 1
    mem_used_mb: Optional[int] = None
    uptime_seconds: float
    # Slice 9d (consensus reviewer C5): integrity verification state
    # for the currently-loaded model. None for stub backend or before
    # first load. Status values:
    #   "verified"            — sha256 matches manifest pin
    #   "byom_no_pin"         — model in manifest but sha256: null
    #   "byom_unknown_model"  — model not in manifest at all
    # Surfaced in super_admin Settings → System so the operator can
    # see whether they're running a factory-blessed binary.
    integrity_status: Optional[str] = None
    integrity_expected_sha256: Optional[str] = None
    integrity_computed_sha256: Optional[str] = None


# ---------------------------------------------------------------------------
# /v1/enrich-note
# ---------------------------------------------------------------------------

class EnrichNoteRequest(BaseModel):
    """Augment a heuristic note with model-generated context.

    Caller supplies:
      - `ref_kind` + `ref_id`: what the note attaches to (event,
        ticket, indicator). Echoed back so the caller can route the
        response without state-keeping. Note: this is NOT used to
        fetch data — the model never reaches across the bridge.
      - `heuristic_note`: the deterministic agent_note text already
        computed by octo-core's heuristic engine.
      - `signals`: a small set of pre-extracted structured signals
        (e.g. "matched_rule:brute-force-ssh", "host_role:domain-controller").
        Cap at 32 entries to bound prompt size.
      - `tenant_scope_slug`: the tenant whose context this is. Echoed
        in the response for audit; the model itself doesn't condition
        on tenant identity (cross-tenant isolation per ADR-003).
      - `query_kind`: selects the server-side prompt template.
        Default `auto_enrich` for background autonomous enrichment;
        the four operator-triggered values map to the canned
        "ask octo" drawer buttons (Rick's 2026-05-21 design call —
        see the octo-llm triage-taxonomy design decision).
    """
    ref_kind: Literal["event", "ticket", "indicator"]
    ref_id: int = Field(ge=1)
    heuristic_note: str = Field(min_length=1, max_length=MAX_NOTE_TEXT)
    signals: list[str] = Field(default_factory=list, max_length=32)
    tenant_scope_slug: str = Field(min_length=1, max_length=128)
    agent_id: AgentId = "octo"
    query_kind: QueryKind = "auto_enrich"


class EnrichNoteResponse(BaseModel):
    """Returns ONLY the structured shape below. The model's raw
    generation is parsed into these fields by the inference layer;
    callers never see the raw text."""
    enriched_text: str = Field(max_length=MAX_NOTE_TEXT)
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: str
    took_ms: int
    # Echoed from request for routing convenience + audit:
    ref_kind: Literal["event", "ticket", "indicator"]
    ref_id: int
    tenant_scope_slug: str
    # Echoed so UI can label the resulting agent_note ("octo · ask:
    # recognized_patterns · 92%") and the audit trail records which
    # canned template fired.
    query_kind: QueryKind = "auto_enrich"
    # Slice 9e (consensus reviewer P3). The confidence value above is
    # NOT calibrated against actual triage outcomes — it's a raw
    # model probability that systematically over-estimates on small
    # local models. Until the calibration loop ships (see #50 + the
    # detection-capability iterative workstream), the bridge marks
    # every response uncalibrated so the UI surface can warn
    # operators not to gate decisions on the number.
    #
    #   "uncalibrated" — default; confidence is a raw model score
    #   "calibrated"   — reserved for post-calibration-loop responses
    calibration_state: Literal["uncalibrated", "calibrated"] = "uncalibrated"


# ---------------------------------------------------------------------------
# /v1/triage-event
# ---------------------------------------------------------------------------

class PeerEventSummary(BaseModel):
    """A neighboring event summary the model can use as context.

    Caller (octo-core) decides what counts as a 'peer' — typically
    same host, same source, within a sliding time window. The peer
    summary is the heuristic_note text for that peer; the model never
    sees the raw event payload."""
    summary: str = Field(min_length=1, max_length=MAX_PEER_SUMMARY_TEXT)
    severity: Severity


class TriageEventRequest(BaseModel):
    """Suggest a severity + rationale for an event.

    Caller supplies:
      - `event_summary`: the deterministic summary from octo-core's
        heuristic.
      - `peer_events`: 0-16 PeerEventSummary entries (recent events
        from the same host/source).
      - `heuristic_severity`: the severity the heuristic computed —
        the LLM is suggesting an adjustment, not a from-scratch
        classification.
      - `tenant_scope_slug`: see EnrichNoteRequest.
    """
    event_summary: str = Field(min_length=1, max_length=MAX_SUMMARY_TEXT)
    peer_events: list[PeerEventSummary] = Field(default_factory=list, max_length=16)
    heuristic_severity: Severity
    tenant_scope_slug: str = Field(min_length=1, max_length=128)
    agent_id: AgentId = "octo"


class TriageEventResponse(BaseModel):
    """Suggested severity adjustment + autonomous disposition.

    Per the octo-llm triage-taxonomy design decision (2026-05-21), the
    response carries BOTH a severity suggestion AND a higher-level
    disposition that the calling octo-core agent acts on:

      - noise     → octo-core auto-suppresses + round-trips closure
      - pattern   → octo-core flags the agent_note + chip; no severity bump
      - escalate  → octo-core bumps severity + creates ticket
      - uncertain → octo-core takes no autonomous action; flag for analyst

    The two fields are correlated but separable: a `disposition:
    escalate` typically lifts severity by one bucket, but the LLM
    may suggest a non-monotonic combination (e.g. `escalate` with
    `suggested_severity: medium` because peer events suggest a
    coordinated low-severity pattern that's actually a critical
    incident in aggregate). The caller respects both.
    """
    suggested_severity: Severity
    rationale_text: str = Field(max_length=MAX_NOTE_TEXT)
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: str
    took_ms: int
    tenant_scope_slug: str
    # True iff the suggestion differs from the heuristic's call.
    # Lets the caller cheaply skip writing an enrichment audit row
    # when the LLM agreed with the heuristic.
    differs_from_heuristic: bool
    # Autonomous-triage taxonomy (2026-05-21).
    disposition: Disposition
    # Why the disposition was chosen. Keeps the operator-facing UI
    # informative when the chip is rendered (hover shows the reason).
    disposition_reason: str = Field(max_length=MAX_NOTE_TEXT)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    """Returned on every non-2xx with a stable shape.

    Status-code semantics:
      400 - validation_error: caller payload didn't conform to schema
      503 - backend_unavailable: model didn't load / backend down
      504 - inference_timeout: request exceeded request_timeout_seconds
      500 - internal_error: catch-all; details suppressed
    """
    error: str
    detail: Optional[str] = None
