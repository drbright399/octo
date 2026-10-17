"""Pluggable inference backend interface.

Slice 1 ships only `StubBackend` which returns canned responses with
model_version "stub-v0". Slice 2 adds `LlamaCppBackend` loading the
Granite 3B Q4 GGUF via llama-cpp-python. Future backends (ollama,
vLLM CPU, GPU passthrough) drop in here.

The backend interface is intentionally narrow — three methods,
parallel to the three external endpoints. This means the API layer
never gets a free-text prompt out of the backend; the backend
itself owns prompt construction + response parsing.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from apps.octo_llm import models


@dataclass(frozen=True)
class BackendHealth:
    """Slice 1: stub backend is always "loaded". Slice 2: reflects
    actual GGUF mmap state. Slice 9d adds the integrity verification
    result so /v1/healthz can surface 'verified' vs 'byom' state."""
    model_loaded: bool
    model_version: str
    mem_used_mb: Optional[int] = None
    integrity_status: Optional[str] = None
    integrity_expected_sha256: Optional[str] = None
    integrity_computed_sha256: Optional[str] = None


class InferenceBackend(ABC):
    """Abstract interface every backend implements.

    Implementations MUST:
      - Validate request semantically beyond Pydantic (e.g., per-call
        prompt-size budget).
      - Construct any prompt internally; never accept caller text
        verbatim into the model.
      - Apply the request-timeout to the inference call itself.
      - Parse model output into the typed response shape; on parse
        failure, fall back to a structured "could not parse" response
        — NEVER return raw model text upstream.
    """

    @abstractmethod
    def health(self) -> BackendHealth:
        """Return current backend state. Called by /v1/healthz."""

    @abstractmethod
    def enrich_note(
        self, req: models.EnrichNoteRequest,
    ) -> models.EnrichNoteResponse:
        """Slice 2+: run the prompt template. Slice 1: canned."""

    @abstractmethod
    def triage_event(
        self, req: models.TriageEventRequest,
    ) -> models.TriageEventResponse:
        """Slice 2+: run the prompt template. Slice 1: canned."""


class StubBackend(InferenceBackend):
    """Canned-response backend for Slice 1 + tests.

    Returns deterministic, traceable responses keyed on the request
    so tests can assert behavior without loading a model. The stub
    is also the safe default for dev environments and CI — no GGUF
    weights required, no llama.cpp dependency.

    What the stub DOES preserve:
      - The structured-response contract (every field is populated).
      - Echoed routing fields (ref_kind, ref_id, tenant_scope_slug).
      - A non-zero `took_ms` so callers' latency histograms behave.
      - A confidence below the 'production-grade' threshold (0.50)
        so any caller that gates on confidence treats stub output
        as advisory only — defense in depth against accidentally
        promoting stub responses to operator-visible state.
    """
    MODEL_VERSION = "stub-v0"
    STUB_CONFIDENCE = 0.50

    def __init__(self) -> None:
        self._started_at = time.time()

    def health(self) -> BackendHealth:
        # Stub is always "loaded" — there's nothing to load. The
        # caller still sees `backend: stub` from the surrounding
        # /healthz response so they can distinguish prod from dev.
        return BackendHealth(
            model_loaded=True,
            model_version=self.MODEL_VERSION,
            mem_used_mb=None,
        )

    # Per-query-kind stub prefix. The real backend in Slice 2 will
    # use these strings to select prompt templates from
    # apps/octo_llm/prompts/<kind>.tpl; the stub returns
    # differentiated canned text so callers + tests can verify the
    # query_kind dispatch is wired end-to-end.
    _QUERY_PREFIX: dict[str, str] = {
        "auto_enrich":          "[stub-v0 auto] ",
        "tell_me_more":         "[stub-v0 ask:tell-more] ",
        "recognized_patterns":  "[stub-v0 ask:patterns] ",
        "compare_recent":       "[stub-v0 ask:compare] ",
        "suggest_disposition":  "[stub-v0 ask:disposition] ",
        "suggest_next_steps":   "[stub-v0 ask:next-steps] ",
    }

    # Stub disposition mapping. Real backend in Slice 2 evaluates
    # peer_events + signals to reach a disposition; the stub keeps
    # the dispatch visible so UI/callers can verify chip rendering
    # across every disposition value without crafting model weights.
    #
    # The mapping reflects the §11.5 rule that the LLM doesn't
    # AUTONOMOUSLY pull severity up unless evidence warrants it:
    #   info / low  → noise    (auto-suppress candidate)
    #   medium      → pattern  (recognized, no severity bump)
    #   high / crit → escalate
    _DISPOSITION_FOR: dict[str, models.Disposition] = {
        "info":     "noise",
        "low":      "noise",
        "medium":   "pattern",
        "high":     "escalate",
        "critical": "escalate",
    }

    def enrich_note(
        self, req: models.EnrichNoteRequest,
    ) -> models.EnrichNoteResponse:
        started = time.monotonic()
        # Stub returns the heuristic note verbatim with a
        # query-kind-specific prefix so callers can see the dispatch
        # in the loop. Slice 2 swaps this for the real prompt
        # template fired against the model.
        prefix = self._QUERY_PREFIX.get(req.query_kind, "[stub-v0] ")
        enriched = f"{prefix}{req.heuristic_note}"
        # Bound to max field length even in stub mode — same invariant
        # the real backend has to enforce.
        if len(enriched) > models.MAX_NOTE_TEXT:
            enriched = enriched[: models.MAX_NOTE_TEXT]
        return models.EnrichNoteResponse(
            enriched_text=enriched,
            confidence=self.STUB_CONFIDENCE,
            model_version=self.MODEL_VERSION,
            took_ms=int((time.monotonic() - started) * 1000),
            ref_kind=req.ref_kind,
            ref_id=req.ref_id,
            tenant_scope_slug=req.tenant_scope_slug,
            query_kind=req.query_kind,
        )

    def triage_event(
        self, req: models.TriageEventRequest,
    ) -> models.TriageEventResponse:
        started = time.monotonic()
        # Stub mirrors heuristic severity (no autonomous bumps) but
        # produces a structured disposition. Real backend may
        # diverge on suggested_severity; tests for the
        # `differs_from_heuristic` flag use a custom backend that
        # does.
        disposition = self._DISPOSITION_FOR[req.heuristic_severity]
        rationale = (
            f"[stub-v0] heuristic severity {req.heuristic_severity} "
            f"confirmed; {len(req.peer_events)} peer event(s) considered"
        )
        disposition_reason = (
            f"[stub-v0] disposition={disposition} mapped from heuristic "
            f"severity {req.heuristic_severity} via fixed table"
        )
        if len(rationale) > models.MAX_NOTE_TEXT:
            rationale = rationale[: models.MAX_NOTE_TEXT]
        if len(disposition_reason) > models.MAX_NOTE_TEXT:
            disposition_reason = disposition_reason[: models.MAX_NOTE_TEXT]
        return models.TriageEventResponse(
            suggested_severity=req.heuristic_severity,
            rationale_text=rationale,
            confidence=self.STUB_CONFIDENCE,
            model_version=self.MODEL_VERSION,
            took_ms=int((time.monotonic() - started) * 1000),
            tenant_scope_slug=req.tenant_scope_slug,
            differs_from_heuristic=False,
            disposition=disposition,
            disposition_reason=disposition_reason,
        )


class LlamaCppBackend(InferenceBackend):
    """Real inference via llama-cpp-python against a local GGUF model.

    Slice 7b. The model file is volume-mounted (or scp'd) into the
    OCTO_LLM_MODEL_PATH path. Loading is lazy on first call so app
    startup stays cheap; if the model file is missing the first call
    raises FileNotFoundError, which the server layer maps to 503
    backend_unavailable.

    The backend is structured-output-only:
      - enrich_note builds a domain-specific prompt from the request
        via apps.octo_llm.prompts.build_enrich_messages
      - triage_event uses build_triage_messages and parses a
        constrained one-line response. On parse failure, falls back
        to the heuristic baseline rather than returning raw text.

    Memory / wall-clock bounded by Settings: max_output_tokens caps
    generation length; request_timeout_seconds is enforced as a soft
    cap on inference time. Reasonable Granite 3B / Qwen 3B inference
    on a modern CPU runs ~20 tok/sec → a 200-token answer in ~10s.
    """
    # Construct lazily so unit tests of the backend module don't
    # try to load a model file.
    def __init__(
        self,
        *,
        model_path,
        threads: int,
        context_tokens: int,
        max_output_tokens: int,
        request_timeout_seconds: float,
        model_name: str = "unknown",
    ) -> None:
        self._model_path = model_path
        self._threads = threads
        self._context_tokens = context_tokens
        self._max_output_tokens = max_output_tokens
        self._request_timeout_seconds = request_timeout_seconds
        self._model_name = model_name
        self._llm = None  # lazy
        self._loaded_at = None
        self._mem_used_mb: Optional[int] = None
        self._started_at = time.time()
        # Populated by _ensure_loaded → integrity.verify_or_raise.
        # Surfaced via /v1/healthz so super_admin can see whether the
        # currently-loaded model was hash-verified against the
        # factory manifest.
        self._integrity_result: Optional[dict] = None

    @property
    def model_version(self) -> str:
        return self._model_name

    def _ensure_loaded(self) -> None:
        if self._llm is not None:
            return
        from llama_cpp import Llama  # lazy import — heavy
        if not self._model_path.exists():
            raise FileNotFoundError(
                f"model file not found at {self._model_path} — "
                f"drop a GGUF there (OCTO_LLM_MODEL_PATH) or switch "
                f"OCTO_LLM_BACKEND=stub for dev",
            )
        # Slice 9d (consensus reviewer C5): verify the on-disk file
        # against the manifest's pinned sha256 BEFORE handing the
        # bytes to llama-cpp. Mismatch raises ModelIntegrityError
        # which propagates to the server startup path so the sibling
        # refuses to come up. BYOM/unpinned files log a warning but
        # still load — see apps/octo_llm/integrity.py.
        from apps.octo_llm.integrity import verify_or_raise
        self._integrity_result = verify_or_raise(
            self._model_name, self._model_path,
        )
        # n_threads=-1 lets llama-cpp pick all cores. n_ctx caps the
        # context window. verbose=False suppresses the chatty load
        # banner so our log prefix stays readable.
        self._llm = Llama(
            model_path=str(self._model_path),
            n_threads=None if self._threads < 0 else self._threads,
            n_ctx=self._context_tokens,
            verbose=False,
        )
        self._loaded_at = time.time()
        # Best-effort memory estimate via psutil if available; not
        # critical, just informational for /v1/healthz.
        try:
            import psutil
            proc = psutil.Process()
            self._mem_used_mb = int(proc.memory_info().rss / (1024 * 1024))
        except Exception:  # noqa: BLE001
            self._mem_used_mb = None

    def health(self) -> BackendHealth:
        # `model_loaded=True` iff we believe the model can serve
        # a request — either we've already lazy-loaded it OR the
        # file exists on disk and will lazy-load on first call.
        # Without this, the bridge precheck blocks the very first
        # request that would trigger the load (chicken-and-egg).
        # The mem_used_mb only populates after a real load.
        loadable = self._llm is not None or self._model_path.exists()
        ir = self._integrity_result or {}
        return BackendHealth(
            model_loaded=loadable,
            model_version=self._model_name,
            mem_used_mb=self._mem_used_mb,
            integrity_status=ir.get("status"),
            integrity_expected_sha256=ir.get("expected_sha256"),
            integrity_computed_sha256=ir.get("computed_sha256"),
        )

    def _generate_chat(self, messages: list[dict]) -> str:
        """Call create_chat_completion. Returns the assistant text."""
        self._ensure_loaded()
        out = self._llm.create_chat_completion(  # type: ignore[union-attr]
            messages=messages,
            max_tokens=self._max_output_tokens,
            temperature=0.4,   # tighter than chat default
            top_p=0.9,
            stream=False,
        )
        # llama-cpp's choices[0].message.content is the assistant reply.
        try:
            return out["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, TypeError):
            return ""

    def enrich_note(
        self, req: models.EnrichNoteRequest,
    ) -> models.EnrichNoteResponse:
        from apps.octo_llm.prompts import build_enrich_messages
        started = time.monotonic()
        text = self._generate_chat(build_enrich_messages(req))
        if not text:
            text = "(model returned empty response; treat as heuristic-only)"
        if len(text) > models.MAX_NOTE_TEXT:
            text = text[: models.MAX_NOTE_TEXT]
        return models.EnrichNoteResponse(
            enriched_text=text,
            # Stable confidence for v1; a future slice can map
            # response shape → calibrated confidence.
            confidence=0.75,
            model_version=self._model_name,
            took_ms=int((time.monotonic() - started) * 1000),
            ref_kind=req.ref_kind,
            ref_id=req.ref_id,
            tenant_scope_slug=req.tenant_scope_slug,
            query_kind=req.query_kind,
        )

    def triage_event(
        self, req: models.TriageEventRequest,
    ) -> models.TriageEventResponse:
        from apps.octo_llm.prompts import build_triage_messages, parse_triage_line
        started = time.monotonic()
        text = self._generate_chat(build_triage_messages(req))
        parsed = parse_triage_line(text) if text else None
        if parsed is None:
            # Model output didn't conform to the structured format.
            # Fall back to the heuristic baseline so we never return
            # raw model text outside the schema.
            return models.TriageEventResponse(
                suggested_severity=req.heuristic_severity,
                rationale_text=(
                    "model output unparseable; falling back to "
                    "heuristic baseline"
                ),
                confidence=0.30,
                model_version=self._model_name,
                took_ms=int((time.monotonic() - started) * 1000),
                tenant_scope_slug=req.tenant_scope_slug,
                differs_from_heuristic=False,
                disposition="uncertain",
                disposition_reason="model output unparseable",
            )
        suggested = parsed["severity"]
        return models.TriageEventResponse(
            suggested_severity=suggested,  # type: ignore[arg-type]
            rationale_text=parsed["reason"][: models.MAX_NOTE_TEXT],
            confidence=0.75,
            model_version=self._model_name,
            took_ms=int((time.monotonic() - started) * 1000),
            tenant_scope_slug=req.tenant_scope_slug,
            differs_from_heuristic=(suggested != req.heuristic_severity),
            disposition=parsed["disposition"],  # type: ignore[arg-type]
            disposition_reason=parsed["reason"][: models.MAX_NOTE_TEXT],
        )


def build_backend(backend_name: str, *, settings=None) -> InferenceBackend:
    """Factory — pick a backend by name.

    "stub"     → StubBackend (Slice 1; default, no model needed)
    "llama-cpp"→ LlamaCppBackend (Slice 7b; requires GGUF on disk)
    """
    name = backend_name.lower().strip()
    if name == "stub":
        return StubBackend()
    if name == "llama-cpp":
        if settings is None:
            raise RuntimeError(
                "llama-cpp backend requires settings to be passed "
                "to build_backend(); the server layer should pass them"
            )
        # Derive a friendly model name from the file stem.
        model_name = settings.model_path.stem or "llama-cpp"
        return LlamaCppBackend(
            model_path=settings.model_path,
            threads=settings.threads,
            context_tokens=settings.context_tokens,
            max_output_tokens=settings.max_output_tokens,
            request_timeout_seconds=settings.request_timeout_seconds,
            model_name=model_name,
        )
    raise ValueError(f"unknown backend: {backend_name!r}")
