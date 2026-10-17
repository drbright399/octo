"""Audit-grade /search export.

Two endpoints, both step-up gated + audit-logged:

  POST /api/v1/search/links/expand
      Body: {refs: [{client_slug, event_id}, ...]}
      Returns: {refs: [{client_slug, event_id, linked_refs: [...]}, ...]}
      One audit entry per call (not per ref) so toolbar's "include
      linked refs" doesn't spam the audit table.

  POST /api/v1/search/export
      Body: {tenants, time_from, time_to, severities, event_types,
             query, source_host,           # same filter shape as /events
             event_ids:[{client_slug,event_id},...],  # explicit selection
             format: 'csv'|'pdf',
             include_linked_refs: bool}
      Returns: streaming response with Content-Disposition: attachment
      Audited as `search.export` with row_count + format + filter_hash
      + delivery=download. The future email delivery (delivery=email,
      recipient list) will route through the same audit shape.

Filter rules: identical to /search/events (scope intersection, 90-day
time window cap, severity allow-list). Selection narrows further —
if `event_ids` is non-empty, only those are exported regardless of
filter. This is the regulator-facing flow: "I selected exactly these
events, here's the export with audit trail."

Branding: PDF header + footer pull from apps.octo.branding.get_branding().
CSV has no branding (it's the raw data format). Audit log records
which branding identity was current at export time (so future "this
report has the old logo" reproducibility queries work).

PDF row cap: 2,000 rows. Beyond that we refuse + suggest CSV. The
intent is auditor-readable handoff, not bulk dump.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from apps.octo import paths
from apps.octo.api.errors import APIError
from apps.octo.api.routers.auth import _audit_append
from apps.octo.api.routers.search import (
    SearchEventsRequest,
    _resolve_caller_scope,
    _intersect_scope,
    _validate_time_range,
    _validate_severities,
    _build_where_clause,
    require_step_up,
    sees_own_records,
    SEARCH_MAX_LIMIT,
)
from apps.octo.auth import sessions
from apps.octo.branding import get_branding
from apps.octo.db import connect
from apps.octo.threat import restricted


router = APIRouter(prefix="/search", tags=["search-export"])


# Caps. Exports run on the read-write API thread so we keep them small;
# anything bigger should hit the future bulk-export pipeline (not yet
# scoped — Task #117 candidate).
EXPORT_PDF_MAX_ROWS = 2_000
EXPORT_CSV_MAX_ROWS = 50_000


# ---------------------------------------------------------------------------
# /links/expand
# ---------------------------------------------------------------------------

class RefId(BaseModel):
    client_slug: str
    event_id: int


class ExpandRequest(BaseModel):
    refs: list[RefId] = Field(min_length=1, max_length=500)


class ExpandedLinkedRef(BaseModel):
    to_kind: str
    to_id: int
    relation: str
    strength: float


class ExpandedRef(BaseModel):
    client_slug: str
    event_id: int
    linked_refs: list[ExpandedLinkedRef]


class ExpandResponse(BaseModel):
    refs: list[ExpandedRef]


@router.post("/links/expand", response_model=ExpandResponse)
def expand_links(
    body: ExpandRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(require_step_up),
) -> ExpandResponse:
    """For each `(client_slug, event_id)`, return its outgoing
    `agent_pattern_links`. One audit entry per call. Scope-enforced —
    refs targeting tenants outside the caller's scope are SILENTLY
    dropped (not 403'd), so the caller's selection harvest never
    discloses scope boundaries.
    """
    request_id = str(uuid.uuid4())
    caller_scope = _resolve_caller_scope(info.operator_id)
    # Group by tenant so we can short-circuit when the tenant isn't in
    # scope and avoid opening a DB we have no business touching.
    by_slug: dict[str, list[int]] = {}
    for r in body.refs:
        by_slug.setdefault(r.client_slug, []).append(r.event_id)

    out: list[ExpandedRef] = []
    for slug, event_ids in by_slug.items():
        # Scope check — caller must see this tenant. Silent skip if not.
        allowed = _intersect_scope(caller_scope, [slug])
        if slug not in allowed:
            for eid in event_ids:
                out.append(ExpandedRef(
                    client_slug=slug, event_id=eid, linked_refs=[],
                ))
            continue
        db_path = paths.client_db_path(slug, "events")
        if not db_path.exists():
            for eid in event_ids:
                out.append(ExpandedRef(
                    client_slug=slug, event_id=eid, linked_refs=[],
                ))
            continue
        conn = connect(db_path, read_only=True)
        conn.row_factory = sqlite3.Row
        try:
            for eid in event_ids:
                try:
                    rows = conn.execute(
                        "SELECT to_kind, to_id, relation, strength "
                        "  FROM agent_pattern_links "
                        " WHERE from_kind = 'event' AND from_id = ? "
                        " ORDER BY strength DESC",
                        (eid,),
                    ).fetchall()
                except sqlite3.OperationalError:
                    # Pre-migration-011 DBs — fall through to empty.
                    rows = []
                out.append(ExpandedRef(
                    client_slug=slug,
                    event_id=eid,
                    linked_refs=[
                        ExpandedLinkedRef(
                            to_kind=r["to_kind"], to_id=r["to_id"],
                            relation=r["relation"], strength=r["strength"],
                        ) for r in rows
                    ],
                ))
        finally:
            conn.close()

    total_links = sum(len(r.linked_refs) for r in out)
    _audit_append(
        "search.links_expand",
        actor=f"operator:{info.operator_id}",
        target_id=None,
        before=None,
        after={
            "ref_count": len(body.refs),
            "tenants_touched": sorted(by_slug.keys()),
            "links_returned": total_links,
            "session_id_prefix": info.id[:8],
        },
        reason="bulk-selection: include linked refs",
        request_id=request_id,
    )
    return ExpandResponse(refs=out)


# ---------------------------------------------------------------------------
# /export
# ---------------------------------------------------------------------------

class ExportRequest(SearchEventsRequest):
    event_ids: list[RefId] = Field(default_factory=list)
    """Explicit selection. Empty → export all rows matching the filter,
    capped at format's row limit. Non-empty → only those rows, scope-
    enforced (refs outside scope are silently dropped)."""
    format: str = Field(default="csv", pattern="^(csv|pdf)$")
    include_agent_notes: bool = False
    """When true, attach the agent_notes attached to each exported
    event. CSV gets an `agent_notes_json` column; PDF gets a new
    'Agent notes' section after the event table. Default off so the
    fast-path stays small."""
    include_indicators: bool = False
    """When true, attach indicators related to the exported events.
    'Related' means: IOC values matching anything pulled out of the
    event's payload (vendor_event_id source_host etc.) AND any
    `agent_pattern_links` from event → indicator. CSV gets a
    `linked_indicators_json` column; PDF gets a 'Related indicators'
    section."""


# Caps for the optional-include data so the export can't blow up
# under a misclick. CSV stays JSON-encoded so the wide column reads
# as one cell to spreadsheet tools; PDF truncates with a "+N more"
# tail because two-column PDF cells don't wrap pretty past ~10 lines.
MAX_NOTES_PER_EVENT_PDF = 8
MAX_INDICATORS_PDF = 1_000


def _filter_hash(req: ExportRequest, tenants_searched: list[str]) -> str:
    """Stable hash over the export's filter+selection. Goes into the
    audit log so an auditor can later prove `report-X.pdf` came from
    `filter-hash=Y`. Reproducibility surface for "show me what this
    operator exported."""
    payload = {
        "tenants": sorted(tenants_searched),
        "event_types": sorted(set(req.event_types)),
        "severities": sorted(set(req.severities)),
        "time_from": req.time_from,
        "time_to": req.time_to,
        "source_host": req.source_host,
        "query": req.query,
        "event_ids": sorted([
            f"{r.client_slug}:{r.event_id}" for r in req.event_ids
        ]),
        "format": req.format,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _gather_rows(req: ExportRequest, tenants: list[str], time_from: Optional[str],
                  time_to: Optional[str], cap: int, *, own_records: bool = True) -> list[dict]:
    """Pull export rows. When event_ids is non-empty, that's the
    universe (filter still applied). When empty, ordinary filtered
    fetch. Returns plain dicts, not Pydantic models — we want the
    flexibility for CSV column control + PDF formatting."""
    selected_ids_by_slug: dict[str, set[int]] = {}
    for r in req.event_ids:
        selected_ids_by_slug.setdefault(r.client_slug, set()).add(r.event_id)

    rows_out: list[dict] = []
    for slug in tenants:
        if req.event_ids and slug not in selected_ids_by_slug:
            continue  # selection-restricted, this tenant has no picks
        db_path = paths.client_db_path(slug, "events")
        if not db_path.exists():
            continue
        where_sql, params = _build_where_clause(req, time_from, time_to,
                                                own_records=own_records)
        if req.event_ids:
            # Narrow further by the selected IDs for this tenant.
            ids = sorted(selected_ids_by_slug[slug])
            placeholders = ",".join("?" * len(ids))
            extra = f"id IN ({placeholders})"
            where_sql = (where_sql + f" AND {extra}") if where_sql \
                else f"WHERE {extra}"
            params = list(params) + ids
        try:
            conn = connect(db_path, read_only=True)
            conn.row_factory = sqlite3.Row
            # RESTRICTED (B7, CSAM): a row naming a restricted domain never
            # leaves Athena in an export — for any role.
            where_sql = restricted.gate_sql(restricted.Gate.for_tenant(slug), conn,
                                            where_sql, "summary", "payload", "source_host")
            try:
                budget = max(0, cap - len(rows_out))
                if budget == 0:
                    break
                rs = conn.execute(
                    f"SELECT id, received_at, source, source_host, event_type, "
                    f"  severity, summary, payload_sha256 "
                    f"FROM events {where_sql} "
                    f"ORDER BY received_at DESC LIMIT ?",
                    (*params, budget),
                ).fetchall()
                for r in rs:
                    rows_out.append({
                        "client_slug": slug,
                        "event_id": r["id"],
                        "received_at": r["received_at"],
                        "source": r["source"],
                        "source_host": r["source_host"],
                        "event_type": r["event_type"],
                        "severity": r["severity"],
                        "summary": r["summary"] or "",
                        "payload_sha256": r["payload_sha256"],
                    })
            finally:
                conn.close()
        except sqlite3.OperationalError:
            continue
        if len(rows_out) >= cap:
            break
    return rows_out


def _attach_agent_notes(rows: list[dict]) -> None:
    """Mutates `rows` in place to add `agent_notes` list per event.
    Each entry: {agent_id, note_text, confidence, created_at}.

    Queries one DB per tenant; events without notes get an empty list.
    Pre-migration-011 DBs silently return empty (try/except OperationalError)."""
    by_slug: dict[str, list[dict]] = {}
    for r in rows:
        by_slug.setdefault(r["client_slug"], []).append(r)
    for slug, slug_rows in by_slug.items():
        db = paths.client_db_path(slug, "events")
        if not db.exists():
            for r in slug_rows:
                r["agent_notes"] = []
            continue
        try:
            conn = connect(db, read_only=True)
            conn.row_factory = sqlite3.Row
            try:
                # Pull all notes for this tenant's selected event ids in
                # one query — cheaper than N round-trips.
                ids = [r["event_id"] for r in slug_rows]
                placeholders = ",".join("?" * len(ids))
                note_rows = conn.execute(
                    f"SELECT ref_id, agent_id, note_text, confidence, "
                    f"  created_at "
                    f"FROM agent_notes "
                    f"WHERE ref_kind = 'event' AND ref_id IN ({placeholders}) "
                    f"ORDER BY created_at DESC",
                    ids,
                ).fetchall()
                by_event: dict[int, list[dict]] = {}
                for nr in note_rows:
                    by_event.setdefault(nr["ref_id"], []).append({
                        "agent_id": nr["agent_id"],
                        "note_text": nr["note_text"],
                        "confidence": nr["confidence"],
                        "created_at": nr["created_at"],
                    })
                for r in slug_rows:
                    r["agent_notes"] = by_event.get(r["event_id"], [])
            finally:
                conn.close()
        except sqlite3.OperationalError:
            for r in slug_rows:
                r["agent_notes"] = []


def _attach_related_indicators(rows: list[dict]) -> None:
    """Mutates `rows` to add `linked_indicators` list per event.

    Two sources combined, de-duped by (value, type):
      1. Anything in the tenant's indicators.db whose `value` appears
         as a substring in the event's payload_sha256, source_host,
         summary, or event_type. (v1 — a future event-extraction pass
         would parse the actual payload JSON; this catches the common
         host + hash overlap cases.)
      2. agent_pattern_links from the event to ref_kind='indicator'
         in the same tenant.

    Conservative scope: per-tenant only. Cross-tenant IOC overlap
    surfaces in the future sanitized-pool variant (M10), NEVER here.
    """
    by_slug: dict[str, list[dict]] = {}
    for r in rows:
        by_slug.setdefault(r["client_slug"], []).append(r)
    for slug, slug_rows in by_slug.items():
        events_db = paths.client_db_path(slug, "events")
        ind_db = paths.client_db_path(slug, "indicators")
        for r in slug_rows:
            r["linked_indicators"] = []
        # First — pattern_links from these events to indicators (in
        # events.db, agent_pattern_links table).
        link_pairs: dict[int, list[int]] = {}  # event_id → indicator_ids
        if events_db.exists():
            try:
                conn = connect(events_db, read_only=True)
                conn.row_factory = sqlite3.Row
                try:
                    ids = [r["event_id"] for r in slug_rows]
                    placeholders = ",".join("?" * len(ids))
                    lk_rows = conn.execute(
                        f"SELECT from_id, to_id FROM agent_pattern_links "
                        f"WHERE from_kind = 'event' AND to_kind = 'indicator' "
                        f"  AND from_id IN ({placeholders})",
                        ids,
                    ).fetchall()
                    for lr in lk_rows:
                        link_pairs.setdefault(lr["from_id"], []).append(lr["to_id"])
                finally:
                    conn.close()
            except sqlite3.OperationalError:
                pass
        # Second — fetch matching indicator rows + value-overlap matches.
        if not ind_db.exists():
            continue
        try:
            iconn = connect(ind_db, read_only=True)
            iconn.row_factory = sqlite3.Row
            try:
                # Build a lookup of all promoted + recent indicators for
                # this tenant (capped) so we can value-match in Python.
                all_ind = iconn.execute(
                    "SELECT id, value, type, severity, confidence, "
                    "       first_seen, last_seen, hits "
                    "  FROM indicators "
                    " WHERE deleted_at IS NULL "
                    " ORDER BY last_seen DESC LIMIT 5000"
                ).fetchall()
                # RESTRICTED (B7, CSAM): an indicator naming a restricted
                # domain is never exported.
                gate = restricted.Gate.for_tenant(slug)
                all_ind = [row for row in all_ind if not gate.hits(row["value"])]
                # Indicator-by-id index for the pattern_link path
                ind_by_id = {row["id"]: row for row in all_ind}
                for r in slug_rows:
                    matched: dict[tuple[str, str], dict] = {}
                    haystack = " ".join(filter(None, [
                        r.get("summary") or "",
                        r.get("source_host") or "",
                        r.get("event_type") or "",
                        r.get("payload_sha256") or "",
                    ])).lower()
                    # Value-overlap path
                    for row in all_ind:
                        if not row["value"]:
                            continue
                        v = row["value"].lower()
                        if v and v in haystack:
                            matched[(row["value"], row["type"])] = dict(row)
                    # Pattern-link path
                    for ind_id in link_pairs.get(r["event_id"], []):
                        if ind_id in ind_by_id:
                            row = ind_by_id[ind_id]
                            matched[(row["value"], row["type"])] = dict(row)
                    # Lift to a list, strip the internal id column.
                    r["linked_indicators"] = [
                        {
                            "value": m["value"], "type": m["type"],
                            "severity": m["severity"],
                            "confidence": m["confidence"],
                            "first_seen": m["first_seen"],
                            "last_seen": m["last_seen"],
                            "hits": m["hits"],
                        } for m in matched.values()
                    ]
            finally:
                iconn.close()
        except sqlite3.OperationalError:
            continue


def _render_csv(
    rows: list[dict], *,
    include_agent_notes: bool, include_indicators: bool,
) -> bytes:
    """RFC-4180 CSV. When optional includes are on, widens the row with
    JSON-encoded columns. Auditor tools (Excel, jq, pandas) all parse
    one JSON-string cell cleanly — better than multi-section CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    header = [
        "client_slug", "event_id", "received_at", "source",
        "source_host", "event_type", "severity", "summary",
        "payload_sha256",
    ]
    if include_agent_notes:
        header.append("agent_notes_json")
    if include_indicators:
        header.append("linked_indicators_json")
    writer.writerow(header)
    for r in rows:
        row_out = [
            r["client_slug"], r["event_id"], r["received_at"], r["source"],
            r["source_host"] or "", r["event_type"], r["severity"],
            r["summary"], r["payload_sha256"],
        ]
        if include_agent_notes:
            row_out.append(json.dumps(r.get("agent_notes", []), separators=(",", ":")))
        if include_indicators:
            row_out.append(json.dumps(r.get("linked_indicators", []), separators=(",", ":")))
        writer.writerow(row_out)
    return buf.getvalue().encode("utf-8")


def _render_pdf(
    rows: list[dict],
    *,
    operator_id: int,
    audit_request_id: str,
    filter_hash: str,
    tenants_searched: list[str],
    time_from: Optional[str],
    time_to: Optional[str],
    branding,
    include_agent_notes: bool = False,
    include_indicators: bool = False,
) -> bytes:
    """Branded PDF report. Header: branding name + accent line + report
    title + filter summary. Body: row table. Footer: operator id,
    timestamp, audit_request_id, filter_hash. All on every page."""
    from reportlab.lib import colors  # local import — reportlab is heavy
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title=f"{branding.name} — Search Audit Export",
        author=branding.name,
    )
    styles = getSampleStyleSheet()
    accent = colors.HexColor(branding.accent_hex)
    ink = colors.HexColor("#000000")
    ink_dim = colors.HexColor("#374151")
    ink_muted = colors.HexColor("#6b7280")

    # Body text stays BLACK regardless of brand palette — some accents
    # (yellow, light cyan) wash out on white paper. Accent is reserved
    # for thin rules + the table header bar where contrast is enforced
    # via the bar's own colored background.
    h1 = ParagraphStyle(
        "h1", parent=styles["Heading1"], textColor=ink,
        fontSize=18, leading=22, spaceAfter=6,
    )
    sub = ParagraphStyle(
        "sub", parent=styles["BodyText"], textColor=ink_muted,
        fontSize=9, leading=12,
    )
    meta = ParagraphStyle(
        "meta", parent=styles["BodyText"], fontName="Courier",
        fontSize=8, leading=11, textColor=ink_dim,
    )

    story: list = []

    # Custom letterhead image — drop-in branding for MSPs that have a
    # corporate PDF header. Sized to fit the body width; aspect-ratio
    # preserved. Falls back silently if the file is missing.
    if branding.pdf_header_image_path:
        try:
            import os as _os
            if _os.path.exists(branding.pdf_header_image_path):
                story.append(Image(
                    branding.pdf_header_image_path,
                    width=7.3 * inch, height=1.0 * inch,
                    kind="proportional",
                ))
                story.append(Spacer(1, 8))
        except Exception:
            # Image load failure must NEVER block an audit export.
            # Fall through to text header.
            pass

    story.extend([
        Paragraph(f"{branding.name} — Search Audit Export", h1),
        Paragraph(
            "Audit-grade event export. Each row corresponds to one "
            "ingested event matching the operator's filters + selection "
            "at export time.", sub,
        ),
        Spacer(1, 10),
    ])

    # Filter summary block — auditor reads top-down: who/when/what/scope.
    when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    filter_lines = [
        f"Generated:     {when}",
        f"Operator ID:   {operator_id}",
        f"Audit RID:     {audit_request_id}",
        f"Filter SHA256: {filter_hash}",
        f"Tenants:       {', '.join(tenants_searched) or '(none)'}",
        f"Time window:   {time_from or '(unbounded)'} → {time_to or '(unbounded)'}",
        f"Row count:     {len(rows):,}",
    ]
    for line in filter_lines:
        story.append(Paragraph(line.replace(" ", "&nbsp;"), meta))
    story.append(Spacer(1, 14))

    # Table — kept tight. Long summaries are truncated; full text lives
    # in the CSV companion or the per-event drawer fetch.
    table_header = ["#", "received_at", "tenant", "type", "sev", "host", "summary"]
    table_rows = [table_header]
    for i, r in enumerate(rows, start=1):
        summ = r["summary"]
        if len(summ) > 80:
            summ = summ[:77] + "…"
        table_rows.append([
            str(i),
            r["received_at"],
            r["client_slug"],
            r["event_type"],
            r["severity"],
            r["source_host"] or "—",
            summ,
        ])
    tbl = Table(
        table_rows, repeatRows=1,
        colWidths=[0.3 * inch, 1.5 * inch, 1.3 * inch, 1.0 * inch,
                   0.5 * inch, 1.1 * inch, 2.0 * inch],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f9fafb")]),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(tbl)

    # Optional sections — agent notes + related indicators. After the
    # event table so an auditor reading top-down sees the events first,
    # the agent reasoning second, IOC context third.
    if include_agent_notes:
        story.append(Spacer(1, 16))
        story.append(Paragraph("Agent notes for selected events", h1))
        story.append(Paragraph(
            "Each note attached to one of the events above. Ordered by "
            "event row number, then most-recent note first. Includes "
            "Shallow / Deep / Athena agent attributions + confidence "
            "scores. Cross-reference back via the event_id.", sub,
        ))
        story.append(Spacer(1, 6))
        notes_rows: list[list[str]] = [
            ["event#", "agent", "conf", "note", "when"],
        ]
        for i, r in enumerate(rows, start=1):
            notes = r.get("agent_notes", [])
            for n in notes[:MAX_NOTES_PER_EVENT_PDF]:
                text = n["note_text"]
                if len(text) > 90:
                    text = text[:87] + "…"
                notes_rows.append([
                    str(i), n["agent_id"],
                    f"{int(round(float(n['confidence']) * 100))}%",
                    text, n["created_at"][:19],
                ])
            if len(notes) > MAX_NOTES_PER_EVENT_PDF:
                notes_rows.append([
                    str(i), "—", "—",
                    f"+{len(notes) - MAX_NOTES_PER_EVENT_PDF} more "
                    "(see CSV companion)", "—",
                ])
        if len(notes_rows) == 1:
            story.append(Paragraph(
                "<i>No agent notes attached to any of the selected "
                "events.</i>", meta,
            ))
        else:
            ntbl = Table(
                notes_rows, repeatRows=1,
                colWidths=[0.45 * inch, 0.7 * inch, 0.45 * inch,
                           4.5 * inch, 1.3 * inch],
            )
            ntbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), accent),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f9fafb")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            story.append(ntbl)

    if include_indicators:
        story.append(Spacer(1, 16))
        story.append(Paragraph("Related indicators", h1))
        story.append(Paragraph(
            "Threat-intel indicators (IOCs) related to the selected "
            "events via value overlap with payload or agent-detected "
            "pattern links. Per-tenant only — cross-tenant pool "
            "matches will appear in a separate report when M10 ships.",
            sub,
        ))
        story.append(Spacer(1, 6))
        seen: set[tuple] = set()
        flat: list[dict] = []
        for r in rows:
            for ind in r.get("linked_indicators", []):
                key = (ind["value"], ind["type"])
                if key in seen:
                    continue
                seen.add(key)
                flat.append(ind)
                if len(flat) >= MAX_INDICATORS_PDF:
                    break
            if len(flat) >= MAX_INDICATORS_PDF:
                break
        ind_rows: list[list[str]] = [
            ["#", "type", "value", "sev", "conf", "hits", "last seen"],
        ]
        for i, ind in enumerate(flat, start=1):
            value_str = ind["value"]
            if len(value_str) > 56:
                value_str = value_str[:53] + "…"
            ind_rows.append([
                str(i), ind["type"], value_str, ind["severity"],
                f"{int(round(float(ind['confidence']) * 100))}%",
                str(ind["hits"]), str(ind["last_seen"])[:19],
            ])
        if len(ind_rows) == 1:
            story.append(Paragraph(
                "<i>No indicators related to the selected events.</i>",
                meta,
            ))
        else:
            itbl = Table(
                ind_rows, repeatRows=1,
                colWidths=[0.3 * inch, 0.6 * inch, 3.4 * inch, 0.55 * inch,
                           0.55 * inch, 0.55 * inch, 1.3 * inch],
            )
            itbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), accent),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f9fafb")]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            story.append(itbl)
            if len(flat) >= MAX_INDICATORS_PDF:
                story.append(Paragraph(
                    f"<i>Truncated at {MAX_INDICATORS_PDF} indicators · "
                    "see CSV companion for the full set.</i>",
                    meta,
                ))

    footer = ParagraphStyle(
        "footer", parent=styles["BodyText"],
        fontSize=7, textColor=colors.HexColor("#6b7280"), alignment=1,
    )

    footer_text = (
        branding.pdf_footer_text
        or f"{branding.name} · audit export · contact {branding.contact_email}"
    )

    def _on_page(canvas, _doc) -> None:
        canvas.saveState()
        # Thin accent rule near top — small enough not to dominate even
        # in the gold palette. Body text remains black for legibility.
        canvas.setStrokeColor(accent)
        canvas.setLineWidth(2)
        canvas.line(0.6 * inch, 10.4 * inch, 8.0 * inch, 10.4 * inch)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(ink_muted)
        canvas.drawString(0.6 * inch, 0.4 * inch, footer_text)
        canvas.drawRightString(
            8.0 * inch, 0.4 * inch,
            f"page {_doc.page} · request {audit_request_id[:8]}",
        )
        canvas.restoreState()

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()


@router.post("/export")
def export_search(
    body: ExportRequest,
    request: Request,
    info: sessions.SessionInfo = Depends(require_step_up),
) -> StreamingResponse:
    """Server-side audit-grade export of selected/filtered events.

    Step-up gated + scope-enforced + audit-logged. Returns a streaming
    Content-Disposition: attachment response. CSV is plain RFC-4180;
    PDF is branded via apps.octo.branding.get_branding() with the
    MSP's bundle identity (name, accent, contact email).
    """
    request_id = str(uuid.uuid4())
    ip = request.client.host if request.client else None

    # Validate + intersect scope (mirrors /events).
    req_severities = _validate_severities(body.severities)
    body = body.model_copy(update={"severities": req_severities})
    time_from, time_to = _validate_time_range(body.time_from, body.time_to)

    caller_scope = _resolve_caller_scope(info.operator_id)
    explicit_tenants = body.tenants or [
        r.client_slug for r in body.event_ids
    ]
    tenants = _intersect_scope(caller_scope, explicit_tenants)
    if not tenants:
        raise APIError("ISOLATION_VIOLATION")

    cap = EXPORT_PDF_MAX_ROWS if body.format == "pdf" else EXPORT_CSV_MAX_ROWS
    rows = _gather_rows(body, tenants, time_from, time_to, cap,
                        own_records=sees_own_records(info.operator_id))
    if body.include_agent_notes:
        _attach_agent_notes(rows)
    if body.include_indicators:
        _attach_related_indicators(rows)
    branding = get_branding()
    f_hash = _filter_hash(body, tenants)

    if body.format == "csv":
        blob = _render_csv(
            rows,
            include_agent_notes=body.include_agent_notes,
            include_indicators=body.include_indicators,
        )
        media_type = "text/csv"
        ext = "csv"
    else:
        blob = _render_pdf(
            rows,
            operator_id=info.operator_id,
            audit_request_id=request_id,
            filter_hash=f_hash,
            tenants_searched=tenants,
            time_from=time_from,
            time_to=time_to,
            branding=branding,
            include_agent_notes=body.include_agent_notes,
            include_indicators=body.include_indicators,
        )
        media_type = "application/pdf"
        ext = "pdf"

    when_compact = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"athena-export-{when_compact}-{request_id[:8]}.{ext}"

    _audit_append(
        "search.export",
        actor=f"operator:{info.operator_id}",
        target_id=None,
        before=None,
        after={
            "format": body.format,
            "row_count": len(rows),
            "tenants_searched": tenants,
            "filter_hash": f_hash,
            "branding_name": branding.name,
            "branding_palette": branding.accent_palette,
            "delivery": "download",
            "included": {
                "agent_notes": body.include_agent_notes,
                "indicators": body.include_indicators,
            },
            "ip": ip,
            "session_id_prefix": info.id[:8],
        },
        reason="audit-grade /search export",
        request_id=request_id,
    )

    return StreamingResponse(
        io.BytesIO(blob),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Athena-Audit-Request-Id": request_id,
            "X-Athena-Filter-Hash": f_hash,
        },
    )
