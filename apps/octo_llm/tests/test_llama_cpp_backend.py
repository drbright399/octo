"""Tests for the LlamaCppBackend (Slice 7b).

The backend lazy-loads its model file so unit tests can exercise the
shape-handling logic (prompt construction, parse fallback, response
shaping) without a real GGUF on disk. A monkeypatched
_generate_chat() simulates model output.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from apps.octo_llm import models
from apps.octo_llm.inference import LlamaCppBackend


def _backend() -> LlamaCppBackend:
    return LlamaCppBackend(
        model_path=Path("/dev/null"),
        threads=-1,
        context_tokens=4096,
        max_output_tokens=512,
        request_timeout_seconds=30.0,
        model_name="test-model",
    )


def _enrich_req(**overrides) -> models.EnrichNoteRequest:
    payload = dict(
        ref_kind="event",
        ref_id=1,
        heuristic_note="Three SSH brute-force attempts in 30s",
        signals=["matched_rule:brute-force-ssh"],
        tenant_scope_slug="acme",
        query_kind="tell_me_more",
    )
    payload.update(overrides)
    return models.EnrichNoteRequest(**payload)


def _triage_req(**overrides) -> models.TriageEventRequest:
    payload = dict(
        event_summary="Outbound to 1.1.1.1",
        peer_events=[],
        heuristic_severity="medium",
        tenant_scope_slug="acme",
    )
    payload.update(overrides)
    return models.TriageEventRequest(**payload)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def test_health_reports_not_loaded_when_model_missing() -> None:
    """No actual file on disk → not loadable → model_loaded=False."""
    b = LlamaCppBackend(
        model_path=Path("/nonexistent/never.gguf"),
        threads=-1, context_tokens=4096, max_output_tokens=512,
        request_timeout_seconds=30.0, model_name="missing",
    )
    h = b.health()
    assert h.model_loaded is False
    assert h.model_version == "missing"


def test_health_reports_loaded_when_file_exists(tmp_path) -> None:
    """Model file present on disk → report loadable, even before the
    first inference call has triggered the lazy load. Without this,
    the bridge precheck blocks every request that would have
    triggered the load (chicken-and-egg)."""
    fake_model = tmp_path / "fake.gguf"
    fake_model.write_bytes(b"\x00")  # any size — health() only stats
    b = LlamaCppBackend(
        model_path=fake_model,
        threads=-1, context_tokens=4096, max_output_tokens=512,
        request_timeout_seconds=30.0, model_name="fake",
    )
    h = b.health()
    assert h.model_loaded is True


# ---------------------------------------------------------------------------
# enrich_note
# ---------------------------------------------------------------------------

def test_enrich_note_returns_structured_response() -> None:
    b = _backend()
    with patch.object(
        b, "_generate_chat",
        return_value="Three SSH attempts in 30s suggests a brute-force probe.",
    ):
        result = b.enrich_note(_enrich_req())
    assert result.enriched_text.startswith("Three SSH")
    assert result.model_version == "test-model"
    assert result.ref_kind == "event"
    assert result.ref_id == 1
    assert result.tenant_scope_slug == "acme"
    assert result.query_kind == "tell_me_more"
    assert 0 <= result.confidence <= 1


def test_enrich_note_empty_model_output_returns_safe_fallback() -> None:
    b = _backend()
    with patch.object(b, "_generate_chat", return_value=""):
        result = b.enrich_note(_enrich_req())
    assert "empty response" in result.enriched_text


def test_enrich_note_oversize_clipped_to_max() -> None:
    b = _backend()
    huge = "x" * (models.MAX_NOTE_TEXT + 500)
    with patch.object(b, "_generate_chat", return_value=huge):
        result = b.enrich_note(_enrich_req())
    assert len(result.enriched_text) <= models.MAX_NOTE_TEXT


# ---------------------------------------------------------------------------
# triage_event
# ---------------------------------------------------------------------------

def test_triage_event_parses_structured_response() -> None:
    b = _backend()
    with patch.object(
        b, "_generate_chat",
        return_value="severity=high; disposition=escalate; reason=brute-force",
    ):
        result = b.triage_event(_triage_req(heuristic_severity="medium"))
    assert result.suggested_severity == "high"
    assert result.disposition == "escalate"
    assert result.differs_from_heuristic is True  # heuristic=medium → suggested=high
    assert "brute-force" in result.rationale_text


def test_triage_event_parse_failure_falls_back_to_heuristic() -> None:
    """Critical safety: if the model output doesn't conform to the
    structured format, we MUST NOT return raw model text. Falls back
    to the heuristic baseline with disposition='uncertain'."""
    b = _backend()
    with patch.object(
        b, "_generate_chat",
        return_value="The threat actor appears to be highly sophisticated...",
    ):
        result = b.triage_event(_triage_req(heuristic_severity="medium"))
    assert result.suggested_severity == "medium"  # baseline
    assert result.disposition == "uncertain"
    assert result.differs_from_heuristic is False
    assert "unparseable" in result.rationale_text


def test_triage_event_empty_model_output_falls_back() -> None:
    b = _backend()
    with patch.object(b, "_generate_chat", return_value=""):
        result = b.triage_event(_triage_req(heuristic_severity="medium"))
    assert result.disposition == "uncertain"
    assert result.suggested_severity == "medium"


def test_triage_event_agrees_with_heuristic_marks_no_diff() -> None:
    b = _backend()
    with patch.object(
        b, "_generate_chat",
        return_value="severity=medium; disposition=pattern; reason=routine",
    ):
        result = b.triage_event(_triage_req(heuristic_severity="medium"))
    assert result.differs_from_heuristic is False
    assert result.disposition == "pattern"


# ---------------------------------------------------------------------------
# Missing model file
# ---------------------------------------------------------------------------

def test_first_call_raises_when_model_missing() -> None:
    """Lazy load fires on first call; if model file is missing, raises
    FileNotFoundError. Server layer maps this to HTTP 503."""
    b = LlamaCppBackend(
        model_path=Path("/nonexistent/path/no-such.gguf"),
        threads=-1,
        context_tokens=4096,
        max_output_tokens=512,
        request_timeout_seconds=30.0,
        model_name="missing",
    )
    with pytest.raises(FileNotFoundError, match="not found"):
        b._ensure_loaded()
