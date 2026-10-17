"""FastAPI app factory + endpoint glue for octo-llm.

Builds the FastAPI app with the three domain endpoints. The backend
is selected at app construction (one backend per process). Errors
return the structured ErrorResponse shape so callers can switch on
`error` strings without parsing English.

Slice 1: stub backend default. App builds + serves with no model.
Slice 2: llama-cpp backend selectable via OCTO_LLM_BACKEND env var.
"""
from __future__ import annotations

import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from apps.octo_llm import inference, models
from apps.octo_llm.config import Settings, load_settings


def create_app(*, settings: Optional[Settings] = None) -> FastAPI:
    """Build the FastAPI app.

    `settings` is injected for tests; production reads env via
    `load_settings()`.
    """
    cfg = settings if settings is not None else load_settings()
    backend = inference.build_backend(cfg.backend, settings=cfg)
    started_at = time.time()

    app = FastAPI(
        title="octo-llm",
        version="0.1.0",
        description=(
            "Layer 2 LLM sibling for the OCTO bundle. Structured-only "
            "input + output. Never load-bearing — callers must fall back "
            "to heuristic-only behavior when this service is unavailable."
        ),
        # Don't expose docs or redoc — this is an internal service.
        # Removing them shrinks the attack surface (no swagger.json
        # for an attacker to enumerate the schema from a stolen
        # docker-network access).
        docs_url=None, redoc_url=None, openapi_url=None,
    )

    # Stash on app state so endpoints can reach them without
    # global mutable state.
    app.state.cfg = cfg
    app.state.backend = backend
    app.state.started_at = started_at

    # Slice 7m — eager-warm the llama-cpp backend on startup so the
    # FIRST inference call doesn't hit the bridge's 35s timeout
    # while the GGUF mmap + ggml warmup runs (Granite 8B Q4 on CPU
    # is ~15-30s; cumulative w/ first inference can exceed 35s).
    # The stub backend has nothing to warm — skipped.
    if hasattr(backend, "_ensure_loaded"):
        try:
            backend._ensure_loaded()  # type: ignore[attr-defined]
        except FileNotFoundError:
            # Model file missing — bridge call later returns 503;
            # operator can drop the file + restart from the UI.
            pass
        except Exception as exc:  # noqa: BLE001
            # Slice 9d (consensus reviewer C5): if integrity
            # verification FAILED, log loudly so the operator sees
            # WHY healthz reports model_loaded=false rather than
            # silent-fail. Any other startup error is also logged so
            # we don't crash-loop on an exotic failure.
            import logging
            logging.getLogger("octo_llm.server").error(
                "octo-llm startup failed to load model: %s", exc,
            )

    @app.get("/v1/healthz", response_model=models.HealthResponse)
    def healthz() -> models.HealthResponse:
        h = backend.health()
        return models.HealthResponse(
            ok=h.model_loaded,
            backend=cfg.backend,
            model_loaded=h.model_loaded,
            model_version=h.model_version,
            mem_used_mb=h.mem_used_mb,
            uptime_seconds=round(time.time() - started_at, 3),
            integrity_status=h.integrity_status,
            integrity_expected_sha256=h.integrity_expected_sha256,
            integrity_computed_sha256=h.integrity_computed_sha256,
        )

    @app.post("/v1/enrich-note", response_model=models.EnrichNoteResponse)
    def enrich_note(req: models.EnrichNoteRequest) -> models.EnrichNoteResponse:
        try:
            return backend.enrich_note(req)
        except (NotImplementedError, FileNotFoundError) as exc:
            # Misconfigured backend or missing model file. 503 so the
            # caller falls back to heuristic-only behavior per the
            # §11.5 "LLM is value-add, never load-bearing" contract.
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "backend_unavailable",
                    "detail": str(exc),
                },
            )

    @app.post("/v1/triage-event", response_model=models.TriageEventResponse)
    def triage_event(req: models.TriageEventRequest) -> models.TriageEventResponse:
        try:
            return backend.triage_event(req)
        except NotImplementedError as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "backend_unavailable",
                    "detail": str(exc),
                },
            )

    # Pydantic validation errors → ErrorResponse shape (not the
    # default FastAPI nested array). Callers in octo-core get a
    # stable error string they can switch on.
    @app.exception_handler(RequestValidationError)
    async def _validation_handler(
        request: Request, exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content=models.ErrorResponse(
                error="validation_error",
                # Errors() includes loc + msg per field. Join up
                # to a small bound so a 100-field payload doesn't
                # produce a 100kB response.
                detail="; ".join(
                    f"{'.'.join(str(p) for p in e.get('loc', []))}: {e.get('msg', '')}"
                    for e in exc.errors()[:8]
                ),
            ).model_dump(),
        )

    # Other HTTPExceptions surface their detail through the same
    # ErrorResponse shape. Strip any raw exception text so traceback
    # detail never lands in a 5xx response body.
    @app.exception_handler(HTTPException)
    async def _http_handler(request: Request, exc: HTTPException) -> JSONResponse:
        if isinstance(exc.detail, dict) and "error" in exc.detail:
            payload = exc.detail
        else:
            payload = {"error": "http_error", "detail": str(exc.detail)}
        return JSONResponse(status_code=exc.status_code, content=payload)

    return app


# Module-level `app` for uvicorn's import-string discovery
# (`uvicorn apps.octo_llm.server:app`). `load_settings()` returns
# defaults when env is unset, so this works in dev + production
# without per-environment glue. Tests construct their own apps via
# `create_app(settings=...)` to inject custom Settings without
# touching os.environ.
app = create_app()
