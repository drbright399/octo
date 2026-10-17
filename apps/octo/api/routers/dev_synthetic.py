"""Dev-only synthetic-traffic control (Task #119f).

Lets the topbar toggle start/stop synthetic event generation so an
operator can watch the autonomous triage worker annotate live traffic.

HARD-GATED: the router is only mounted when `synthetic_allowed()` is true
(OCTO_DEV_SYNTHETIC=1 + a dev data-root), and each handler re-checks. In
production the router doesn't exist and these paths 404. There is no
auth bypass in dev either: this is test-data tooling, not an auth path —
it still requires an authenticated session.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from apps.octo.api.errors import APIError
from apps.octo.api.routers.auth import session_identity
from apps.octo.auth import sessions
from apps.octo.dev.synthetic_traffic import synthetic_allowed

router = APIRouter(prefix="/dev", tags=["dev"])


class SyntheticStatus(BaseModel):
    allowed: bool
    enabled: bool
    emitted_total: int
    last_emit_at: str | None = None
    interval_seconds: int | None = None


class SyntheticToggle(BaseModel):
    enabled: bool


def _generator_or_404(request: Request):
    if not synthetic_allowed():
        raise APIError("NOT_FOUND", "resource not found")
    gen = getattr(request.app.state, "synthetic_traffic", None)
    if gen is None:
        raise APIError("NOT_FOUND", "resource not found")
    return gen


@router.get("/synthetic-traffic", response_model=SyntheticStatus)
def get_synthetic_traffic(
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> SyntheticStatus:
    return SyntheticStatus(**_generator_or_404(request).status())


@router.post("/synthetic-traffic", response_model=SyntheticStatus)
def set_synthetic_traffic(
    body: SyntheticToggle,
    request: Request,
    info: sessions.SessionInfo = Depends(session_identity),
) -> SyntheticStatus:
    gen = _generator_or_404(request)
    gen.set_enabled(body.enabled)
    return SyntheticStatus(**gen.status())
