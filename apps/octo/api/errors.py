"""Structured JSON error handling — spec §6.1.

All error bodies have shape: `{code, message, request_id}`. Codes are stable
strings (clients may pattern-match).

A `paths.SlugError` that a route does not handle itself (a malformed tenant
slug from a wildcard caller, or a client path the containment check refuses:
one that would leave its root or cross a symlink in the data tree) is
answered as a resource that does not exist: 404 NOT_FOUND, never a 500, and
never naming the refused value.
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from apps.octo.paths import SlugError

logger = logging.getLogger(__name__)

ERROR_CODES = {
    "AUTH_MISSING":          (401, "Authorization header missing or malformed"),
    "AUTH_INVALID":          (401, "bearer token did not resolve"),
    "CLIENT_NOT_FOUND":      (404, "client slug not found"),
    "CLIENT_DISABLED":       (423, "ingestion disabled for this client"),
    "VALIDATION_FAILED":     (422, "request body failed validation"),
    "PAYLOAD_TOO_LARGE":     (413, "request body too large"),
    "ISOLATION_VIOLATION":   (403, "token scope does not cover the requested client"),
    "RATE_LIMITED":          (429, "rate limit exceeded"),
    "CONFLICT":              (409, "conflicting state"),
    "OPERATOR_EXISTS":       (409, "an operator with that username or email already exists"),
    "NOT_FOUND":             (404, "resource not found"),
    "METHOD_NOT_ALLOWED":    (405, "method not allowed on this resource"),
    "PURGE_REFUSED":         (409, "purge refused — client must be offboarded first"),
    "TOKEN_KIND_MISMATCH":   (403, "token kind is not permitted for this endpoint"),
    # F.4b — source-instance ingestion errors
    "TOKEN_NOT_SOURCE_BOUND":   (403, "service token has no source_instance binding"),
    "UNKNOWN_SOURCE_TYPE":      (404, "source_type is not registered"),
    "SOURCE_INSTANCE_MISMATCH": (403, "token's source_instance does not match URL source_type"),
    "SOURCE_INSTANCE_REVOKED":  (403, "source instance has been revoked"),
    # G.1 — Athena Console auth surface
    "AUTH_PASSWORD_INVALID":      (401, "username or password incorrect"),
    "AUTH_TOTP_REQUIRED":         (401, "TOTP code required to complete authentication"),
    "AUTH_TOTP_INVALID":          (401, "TOTP code did not verify"),
    "AUTH_CHALLENGE_EXPIRED":     (401, "sign-in timed out; enter your password again"),
    "AUTH_PASSWORD_REQUIRED_FIRST": (409, "set a password before enrolling MFA"),
    "AUTH_LOCKED":                (423, "account locked due to repeated failed logins"),
    "AUTH_SESSION_INVALID":       (401, "session does not resolve or has expired"),
    "AUTH_SESSION_REVOKED":       (401, "session has been revoked"),
    "AUTH_MAGIC_LINK_INVALID":    (401, "magic link is invalid or expired"),
    "AUTH_MAGIC_LINK_USED":       (409, "magic link has already been consumed"),
    "AUTH_PASSKEY_INVALID":       (401, "passkey assertion did not verify"),
    "AUTH_PASSKEY_NOT_REGISTERED":(404, "no passkeys registered for this operator"),
    "AUTH_MFA_NOT_ENROLLED":      (412, "operator has no MFA factor enrolled"),
    "AUTH_BOOTSTRAP_KEY_INVALID": (401, "bootstrap key did not verify or has been revoked"),
    "AUTH_OPERATOR_NOT_FOUND":    (404, "no operator with that username"),
    "AUTH_OPERATOR_DISABLED":     (423, "operator account is disabled"),
    "AUTH_DUAL_CONTROL_REQUIRED": (412, "second super_admin co-acknowledgement required"),
    "AUTH_DUAL_CONTROL_EXPIRED":  (410, "co-acknowledgement window expired"),
    "AUTH_AI_ACCESS_REVOKED":     (403, "AI access not granted or expired"),
    "AUTH_NO_ATHENA_ACCOUNT":     (403, "no Athena account exists for this identity"),
    "STEP_UP_REQUIRED":           (401, "this surface requires re-authentication (step-up auth)"),
    "STEP_UP_NETWORK_CHANGED":    (401, "step-up clearance was granted from a different network; please re-authenticate"),
    # v0.10 — the attested single-person tenant merge / offboard. Each names
    # the ONE missing piece, so the console can say exactly what to fix.
    "ATTESTATION_REQUIRED":       (422, "a typed attestation of at least 40 characters is required"),
    "SUBJECT_CONFIRMATION_MISMATCH": (422, "the typed tenant slug does not match the tenant being changed"),
    "SINGLE_PERSON_INELIGIBLE":   (409, "the single-person exception does not apply here; file a two-person request"),
    # Adapter framework
    "ADAPTER_NOT_FOUND":         (404, "no adapter registered with that slug"),
    "SMOKE_TEST_FAILED":         (400, "credentials did not pass smoke test"),
    "INSTANCE_ALREADY_EXISTS":   (409, "an active instance for this vendor already exists"),
    # A saved instance's vendor refused or failed an on-demand request. Never
    # 401/403: those mean OUR session/authz to the console and its redirects.
    "VENDOR_ACCESS_FORBIDDEN":   (424, "the vendor accepted the credentials but refuses access to this data"),
    "VENDOR_CREDENTIALS_REJECTED": (424, "the vendor rejected the stored credentials"),
    "VENDOR_UNREACHABLE":        (503, "the vendor could not be reached or answered unexpectedly"),
    "INSTANCE_CREATE_INCOMPLETE": (500, "the integration could not be fully created and was switched off again; try again"),
    # PSA writes kill switch (slice 0): nothing may be queued for Autotask
    # while a super_admin has not switched writes on.
    "PSA_WRITES_DISABLED":       (409, "writes to the PSA (Autotask) are switched off; nothing was queued"),
    "SETUP_REQUIRED":            (403, "account setup is incomplete"),
    "INTERNAL_ERROR":        (500, "internal error"),
    # Octo-LLM bridge surface (Slice 4) — fail-closed UX. UI treats
    # both as "octo unavailable; heuristic only" and never escalates
    # to a hard error.
    "PRECONDITION_FAILED":   (412, "precondition not met"),
    "SERVICE_UNAVAILABLE":   (503, "downstream service unavailable"),
}


class APIError(Exception):
    def __init__(
        self,
        code: str,
        message: Optional[str] = None,
        status: Optional[int] = None,
        request_id: Optional[str] = None,
    ):
        if code not in ERROR_CODES:
            raise ValueError(f"unknown error code: {code}")
        default_status, default_message = ERROR_CODES[code]
        self.code = code
        self.message = message or default_message
        self.status = status or default_status
        self.request_id = request_id or str(uuid.uuid4())
        super().__init__(f"{code}: {self.message}")


# What a client needs to fix a malformed request: WHERE, WHAT KIND, and the
# human sentence. Pydantic also reports `input` (the offending value — for a
# missing key, the WHOLE enclosing body) and `ctx` (which can repeat it); a
# request that failed validation may carry credentials, so neither is echoed.
_SAFE_ERROR_KEYS = ("type", "loc", "msg")


def _safe_validation_errors(exc: RequestValidationError) -> list[dict]:
    return [
        {k: err[k] for k in _SAFE_ERROR_KEYS if k in err}
        for err in exc.errors()
    ]


def _api_error_response(exc: APIError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status,
        content={
            "code": exc.code,
            "message": exc.message,
            "request_id": exc.request_id,
        },
    )


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def api_error_handler(request: Request, exc: APIError):
        return _api_error_response(exc)

    @app.exception_handler(SlugError)
    async def slug_error_handler(request: Request, exc: SlugError):
        # Fail closed as "no such resource": the same body as
        # APIError("NOT_FOUND"), with its fixed message, so neither the
        # refused slug nor the data-root path in exc's text reaches the
        # client. Routes that map SlugError themselves never get here.
        # The log names the route TEMPLATE (never the raw URL, which is
        # caller input) and exc's text, whose values paths.py repr()s.
        route = request.scope.get("route")
        logger.warning(
            "path layer refused %s %s; answered 404: %s",
            request.method, getattr(route, "path", "<unrouted>"), exc,
        )
        return _api_error_response(APIError("NOT_FOUND"))

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "code": "VALIDATION_FAILED",
                "message": "request failed validation",
                "request_id": str(uuid.uuid4()),
                "errors": _safe_validation_errors(exc),
            },
            # A rejected body may have held a secret; nothing about the
            # exchange belongs in a cache.
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        code = {
            401: "AUTH_INVALID",
            403: "ISOLATION_VIOLATION",
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            422: "VALIDATION_FAILED",
            423: "CLIENT_DISABLED",
            429: "RATE_LIMITED",
        }.get(exc.status_code, "INTERNAL_ERROR")
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "code": code,
                "message": str(exc.detail) if exc.detail else ERROR_CODES.get(code, (0, ""))[1],
                "request_id": str(uuid.uuid4()),
            },
        )
