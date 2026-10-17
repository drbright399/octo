"""HTTP-backed BridgeClient — Athena's counterpart to OCTO's bridge router.

Per ADR-004. This module implements the `BridgeClient` Protocol from
shared_bridge by issuing HTTP calls against the OCTO bridge router
endpoints. It's the standard transport for Athena → OCTO data calls in
the bundle deployment + the only transport in a tier-split deployment.

The client:
- Holds a SessionContext (constructed at operator login; per invariant 3
  cannot be retargeted mid-session — to switch tenants, end the session
  and start a new one).
- Holds a bearer token that the OCTO router resolves back to the same
  SessionContext via its BearerTokenResolver.
- Maps HTTP error responses back to InvariantViolation so callers can
  pattern-match on the contract violation rather than HTTP status codes.

Errors:
- 4xx with a JSON body containing {"detail": {"invariant": N, ...}} →
  InvariantViolation(N, message)
- Other 4xx/5xx → BridgeClientError with status + body for triage.
- Network / timeout errors → BridgeClientError wrapping the cause.

The client is constructed against an httpx.Client (or compatible) so
tests can inject a transport that routes to an in-process FastAPI app
without going over the network.
"""

from __future__ import annotations

from typing import Any

import httpx
from shared_bridge import (
    InvariantViolation,
    QueryResult,
    SessionContext,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class BridgeClientError(Exception):
    """Catch-all for HTTP transport errors that aren't contract violations.

    Carries `status_code` (None for transport-level failures) and the raw
    response body when one is available, so callers can log enough to
    triage without re-issuing the failed call.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class HttpBridgeClient:
    """BridgeClient implementation backed by HTTP.

    Construction:

        HttpBridgeClient(
            base_url="http://octo-core:8001",
            token="opaque-bearer-from-auth-core",
            session=SessionContext(...),
            client=httpx.Client(timeout=10.0),  # optional
        )

    Caller is responsible for the lifecycle of the underlying httpx.Client.
    Pass `client=None` (the default) to have the constructor make one with
    sensible defaults; call `.close()` when done in that case.
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        session: SessionContext,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        # Normalize base_url to no-trailing-slash so urljoin paths are clean.
        self._base_url = base_url.rstrip("/")
        self._token = token
        self.session: SessionContext = session
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)

    def close(self) -> None:
        """Release the underlying httpx.Client iff this instance owns it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HttpBridgeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # BridgeClient Protocol surface
    # ------------------------------------------------------------------

    def execute(
        self,
        template_id: str,
        params: dict[str, Any],
    ) -> QueryResult:
        """POST /bridge/v1/execute. Maps HTTP errors back to InvariantViolation."""
        response = self._post("/bridge/v1/execute", json={
            "template_id": template_id,
            "params": params,
        })

        if response.status_code == 200:
            body = response.json()
            return QueryResult(
                template_id=body["template_id"],
                rows=body["rows"],
                row_count=body["row_count"],
                elapsed_ms=body["elapsed_ms"],
                audit_entry_id=body["audit_entry_id"],
            )

        # Try to map known error shapes back into the contract
        _raise_invariant_or_client_error(response, template_id=template_id)
        # _raise_invariant_or_client_error always raises; this is unreachable
        raise AssertionError("unreachable")  # pragma: no cover

    def health(self) -> dict[str, Any]:
        """GET /bridge/v1/health. No auth required by the contract."""
        try:
            response = self._client.get(f"{self._base_url}/bridge/v1/health")
        except httpx.HTTPError as exc:
            raise BridgeClientError(
                f"health probe failed: {exc!r}",
            ) from exc

        if response.status_code != 200:
            raise BridgeClientError(
                f"health probe returned {response.status_code}",
                status_code=response.status_code,
                body=_safe_json(response),
            )
        return response.json()

    # ------------------------------------------------------------------
    # Private — request issuance with auth header
    # ------------------------------------------------------------------

    def _post(self, path: str, *, json: Any) -> httpx.Response:
        try:
            return self._client.post(
                f"{self._base_url}{path}",
                json=json,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            raise BridgeClientError(
                f"transport error on POST {path}: {exc!r}",
            ) from exc

    def _get(self, path: str, *, params: dict[str, Any] | None = None) -> httpx.Response:
        try:
            return self._client.get(
                f"{self._base_url}{path}",
                params=params,
                headers={"Authorization": f"Bearer {self._token}"},
            )
        except httpx.HTTPError as exc:
            raise BridgeClientError(
                f"transport error on GET {path}: {exc!r}",
            ) from exc


# ---------------------------------------------------------------------------
# Error translation
# ---------------------------------------------------------------------------

def _raise_invariant_or_client_error(
    response: httpx.Response,
    *,
    template_id: str,
) -> None:
    """Inspect a non-200 response and raise the correct exception type."""
    body = _safe_json(response)
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, dict) and "invariant" in detail:
        invariant = int(detail["invariant"])
        message = str(detail.get("message") or detail)
        raise InvariantViolation(invariant, message)
    raise BridgeClientError(
        f"bridge call failed for template '{template_id}': "
        f"HTTP {response.status_code}",
        status_code=response.status_code,
        body=body,
    )


def _safe_json(response: httpx.Response) -> Any:
    """response.json() that doesn't blow up on non-JSON bodies."""
    try:
        return response.json()
    except Exception:  # noqa: BLE001 — any decode failure is fine, we just fall through
        return response.text
