"""Step-up authentication for sensitive-surface access.

The /search/* endpoints (client DB query) require a recently-confirmed
identity beyond the standard session cookie. This module owns the
state machine + sliding-window math.

State machine
-------------

- A fresh session has both step_up_auth_granted_at and step_up_auth_until
  NULL → no elevation.
- `grant(session_id)` is called by /search/elevate after the operator
  re-verifies password + TOTP. Sets:
    granted_at = now
    until      = now + STEP_UP_TTL
- `slide(session_info)` is called from `require_step_up()` on every
  /search/* action. Bumps `until` to max(current, now + STEP_UP_TTL),
  but capped at granted_at + STEP_UP_ABSOLUTE_CAP. After the absolute
  cap is reached, the next request is rejected with STEP_UP_REQUIRED.
- `revoke(session_id)` clears both columns. Called on logout + when
  IP changes (defense-in-depth).

TTL defaults
------------

- STEP_UP_TTL          = 30 minutes (sliding)
- STEP_UP_ABSOLUTE_CAP = 4 hours    (hard cap from grant time)

Per the 2026-05-12 client-search design,
both are env-overridable on a per-bundle basis so MSPs with stricter
compliance regimes can tighten and laid-back teams can loosen.

Audit
-----

`grant()` writes a `step_up_granted` audit row.
Failed `grant()` attempts (wrong password / wrong TOTP) write
`step_up_failed`. Successful slides do NOT audit each time — the search
action itself is the load-bearing log entry.
"""
from __future__ import annotations

import ipaddress
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Literal, Optional, Union

from apps.octo.db import connect, transaction
from apps.octo import paths
from apps.octo.auth import sessions


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _ttl_minutes() -> int:
    """Sliding window TTL in minutes. Default 30."""
    raw = os.environ.get("SEARCH_STEP_UP_TTL_MINUTES", "30").strip()
    try:
        v = int(raw)
    except ValueError:
        return 30
    # Clamp to sane range — never less than 5 minutes (UX trap if an
    # operator gets booted mid-typing), never more than 4 hours (defeats
    # the purpose of step-up).
    return max(5, min(240, v))


def _absolute_cap_hours() -> int:
    """Absolute hard cap in hours from grant time. Default 4."""
    raw = os.environ.get("SEARCH_STEP_UP_ABSOLUTE_HOURS", "4").strip()
    try:
        v = int(raw)
    except ValueError:
        return 4
    # Clamp 1..24h. The session itself absolute-expires at 24h, so
    # >24h here serves no purpose.
    return max(1, min(24, v))


IPBindingMode = Literal["strict", "subnet", "off"]


def ip_binding_mode() -> IPBindingMode:
    """Step-up IP binding mode — env override SEARCH_STEP_UP_IP_BINDING.
    Default 'subnet' — middle-ground: meaningful security boost without
    booting every VPN-flap or WiFi-handoff. See Task #102 for the
    deeper conversation queued before next live ship."""
    raw = os.environ.get("SEARCH_STEP_UP_IP_BINDING", "subnet").strip().lower()
    if raw in ("strict", "subnet", "off"):
        return raw  # type: ignore[return-value]
    return "subnet"


def compute_ip_prefix(ip_str: Optional[str], mode: Optional[IPBindingMode] = None) -> Optional[str]:
    """Return a canonical network-prefix string for the request IP.

    Returns None when:
      - mode='off' (binding disabled)
      - ip_str is missing or unparseable

    For mode='strict': returns "<ip>/32" or "<ip>/128"
    For mode='subnet': returns "/24" prefix (IPv4) or "/48" prefix (IPv6)
    """
    if mode is None:
        mode = ip_binding_mode()
    if mode == "off":
        return None
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return None
    if mode == "strict":
        return f"{ip.compressed}/{32 if ip.version == 4 else 128}"
    # subnet
    prefixlen = 24 if ip.version == 4 else 48
    network = ipaddress.ip_network(f"{ip.compressed}/{prefixlen}", strict=False)
    return str(network)


def request_ip_from_headers(
    forwarded_for: Union[None, str, Iterable[str]], client_host: Optional[str],
) -> Optional[str]:
    """The address step-up binds to, for a request whose socket peer is
    `client_host` and whose X-Forwarded-For line(s) are `forwarded_for`:
    the same answer as `apps.octo.api.client_ip.client_ip()` (search.py
    calls that directly with the request).

    X-Forwarded-For is believed only from a peer in OCTO_TRUSTED_PROXIES,
    walked from the right; with the setting empty (or from any other peer)
    the answer is the socket peer. It never takes the LEFT-most entry: that
    one is whatever the first client wrote, so a stolen-cookie holder could
    claim the victim's network. None when there is no peer at all."""
    # Imported here: apps.octo.api imports the routers, which import this.
    from apps.octo.api import client_ip as cip

    address = cip.resolve_client_ip(client_host, forwarded_for, cip.trusted_proxies())
    return None if address == cip.UNKNOWN_PEER else address


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Status helper (read-only)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StepUpStatus:
    elevated: bool
    granted_at: Optional[datetime]
    expires_at: Optional[datetime]   # sliding upper bound (until)
    absolute_expires_at: Optional[datetime]  # granted_at + cap
    ttl_minutes: int
    absolute_cap_hours: int


def status_for(info: sessions.SessionInfo) -> StepUpStatus:
    """Compute the current elevation status without mutating anything."""
    now = _now()
    granted = info.step_up_auth_granted_at
    until = info.step_up_auth_until
    cap = (granted + timedelta(hours=_absolute_cap_hours())) if granted else None
    elevated = bool(
        granted is not None
        and until is not None
        and until > now
        and cap is not None
        and now < cap
    )
    return StepUpStatus(
        elevated=elevated,
        granted_at=granted,
        expires_at=until,
        absolute_expires_at=cap,
        ttl_minutes=_ttl_minutes(),
        absolute_cap_hours=_absolute_cap_hours(),
    )


# ---------------------------------------------------------------------------
# State mutations
# ---------------------------------------------------------------------------

def grant(session_id: str, ip_address: Optional[str] = None) -> StepUpStatus:
    """Mark a session as freshly step-up-authenticated.

    Idempotent: re-running re-anchors granted_at = now, restarting the
    4-hour absolute window. That's intentional — operator who proves
    identity again deserves a fresh window.

    `ip_address` is the operator's request IP at elevation time.
    The configured `ip_binding_mode()` decides what prefix to persist
    (or whether to persist any). Pass None on mode='off' deployments.
    """
    now = _now()
    until = now + timedelta(minutes=_ttl_minutes())
    prefix = compute_ip_prefix(ip_address)
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            cur = reg.execute(
                "UPDATE sessions SET "
                "  step_up_auth_granted_at = ?, "
                "  step_up_auth_until = ?, "
                "  step_up_auth_ip_prefix = ? "
                "WHERE id = ? AND revoked_at IS NULL",
                (_iso(now), _iso(until), prefix, session_id),
            )
            if cur.rowcount != 1:
                raise StepUpError("session not found or revoked")
    finally:
        reg.close()
    return StepUpStatus(
        elevated=True,
        granted_at=now,
        expires_at=until,
        absolute_expires_at=now + timedelta(hours=_absolute_cap_hours()),
        ttl_minutes=_ttl_minutes(),
        absolute_cap_hours=_absolute_cap_hours(),
    )


def check_ip_binding(info: sessions.SessionInfo, current_ip: Optional[str]) -> bool:
    """Compare the current request IP against the prefix recorded at
    elevation time. Returns True if the binding holds (or is disabled).

    - mode='off' → always True (no binding to check)
    - mode='strict' / 'subnet' + stored prefix is None → no recorded
      prefix to compare (legacy session pre-migration-010) → True for
      back-compat
    - else compute current_ip's prefix in the same mode and compare
    """
    mode = ip_binding_mode()
    if mode == "off":
        return True
    if info.step_up_auth_ip_prefix is None:
        return True  # legacy pre-migration-010 session
    current_prefix = compute_ip_prefix(current_ip, mode)
    return current_prefix is not None and current_prefix == info.step_up_auth_ip_prefix


def slide(info: sessions.SessionInfo) -> StepUpStatus:
    """Extend the sliding window on a session that's already elevated.

    Returns the post-slide status. Raises StepUpError if the session
    is NOT elevated (caller forgot to check) or has hit the absolute cap.
    """
    now = _now()
    if info.step_up_auth_granted_at is None or info.step_up_auth_until is None:
        raise StepUpError("session is not step-up elevated")
    cap = info.step_up_auth_granted_at + timedelta(hours=_absolute_cap_hours())
    if now >= cap:
        # Absolute cap hit — clear the elevation and refuse.
        revoke(info.id)
        raise StepUpError("step-up absolute cap reached; re-auth required")
    if now >= info.step_up_auth_until:
        # Sliding window already expired — caller should have caught this
        # via require_step_up; raising loud here is a safety belt.
        raise StepUpError("step-up window expired; re-auth required")
    # Slide: new until = max(current, now + ttl), capped at cap.
    candidate = now + timedelta(minutes=_ttl_minutes())
    new_until = min(max(info.step_up_auth_until, candidate), cap)
    if new_until != info.step_up_auth_until:
        reg = connect(paths.registry_db_path())
        try:
            with transaction(reg):
                reg.execute(
                    "UPDATE sessions SET step_up_auth_until = ? WHERE id = ?",
                    (_iso(new_until), info.id),
                )
        finally:
            reg.close()
    return StepUpStatus(
        elevated=True,
        granted_at=info.step_up_auth_granted_at,
        expires_at=new_until,
        absolute_expires_at=cap,
        ttl_minutes=_ttl_minutes(),
        absolute_cap_hours=_absolute_cap_hours(),
    )


def revoke(session_id: str) -> None:
    """Clear elevation on a session — used on logout, IP change, or
    when the absolute cap is hit. Idempotent — works even if the
    session was never elevated."""
    reg = connect(paths.registry_db_path())
    try:
        with transaction(reg):
            reg.execute(
                "UPDATE sessions SET "
                "  step_up_auth_granted_at = NULL, "
                "  step_up_auth_until = NULL, "
                "  step_up_auth_ip_prefix = NULL "
                "WHERE id = ?",
                (session_id,),
            )
    finally:
        reg.close()


class StepUpError(Exception):
    """Raised by step_up.slide() when elevation can't be extended."""
