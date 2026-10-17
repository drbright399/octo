"""Vendor-contact health — a poller tells the platform how its last contact
with the vendor went, and the instance row follows.

Before this, `adapter_instances.status` was written once, by
`InstanceManager.start_instance` ('running' / 'started'), and never again: a
poller whose every request was refused kept logging a warning a minute while
the Integrations card went on saying the integration was healthy. The rule
this module enforces: the platform never claims an integration is healthy
while its most recent contact with the vendor failed.

Adapter-agnostic on purpose. A poller owns one `ContactReporter` and calls
`ok()` after a successful vendor round-trip and `failed(kind, detail)` after a
failed one. The reporter

  * writes the row on TRANSITIONS only — the first report after start, and
    whenever what the operator would read changes — not once per poll;
  * sets status_detail outright (no COALESCE), so a recovered instance never
    keeps a stale error line;
  * never touches a disabled row (a poller can report once more while its
    stop is still being delivered);
  * never raises into the poll loop — a registry hiccup must not stop polling;
  * keeps "last successful contact" in memory for the card (process-local,
    like the dropped-unmapped counters; resets on restart).

Status values are the ones the row's CHECK constraint already allows:
'running' while contact works, 'error' while it does not.

`detail` is operator-visible. The CALLER guarantees it holds no credential,
token or raw vendor body; the reporter only bounds and flattens it.

`FailureBackoff` is the matching retry policy for failures that stay failed
until a human acts (forbidden / rejected credentials): back off, never stop.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from apps.octo.ingest.timestamps import utcnow_iso

logger = logging.getLogger(__name__)

# forbidden — authenticated, but the vendor refuses the data (fix on their side)
# auth      — the vendor rejected the credentials
# transport — unreachable / unexpected answer
# internal  — the poll itself blew up on our side
FailureKind = Literal["forbidden", "auth", "transport", "internal"]

# Holds the longest adapter guidance (instruction + retry note + a bounded
# vendor quotation) WITHOUT cutting it: a truncated instruction is worse
# than a long one.
MAX_DETAIL_CHARS = 800
OK_DETAIL = "connected — last contact with the vendor succeeded"


@dataclass
class _Contact:
    last_ok_at: Optional[str] = None
    last_failed_at: Optional[str] = None
    failure_kind: Optional[str] = None
    consecutive_failures: int = 0
    # The vendor is rate limiting (NextDNS: HTTP 403 right after a success).
    # Not a failure: the row stays 'running' and says so.
    last_throttled_at: Optional[str] = None
    # The first failure of the current run of failures (cleared by a
    # success) — what detection-blindness (FR2) measures "for > 60 min" by.
    failing_since: Optional[str] = None


_lock = threading.Lock()
_contacts: dict[int, _Contact] = {}


def snapshot(instance_id: Optional[int]) -> dict:
    """`{last_ok_at, last_failed_at, failure_kind, consecutive_failures,
    last_throttled_at, failing_since}` for one instance; all-empty when
    nothing has been reported since restart."""
    with _lock:
        entry = _contacts.get(instance_id) if instance_id is not None else None
        if entry is None:
            entry = _Contact()
        return {
            "last_ok_at": entry.last_ok_at,
            "last_failed_at": entry.last_failed_at,
            "failure_kind": entry.failure_kind,
            "consecutive_failures": entry.consecutive_failures,
            "last_throttled_at": entry.last_throttled_at,
            "failing_since": entry.failing_since,
        }


# What a NON-admin (analyst dashboard) reads for a failing instance: fixed,
# platform-authored sentences. `status_detail` can quote vendor text and names
# admin-only remedies, so it stays on the admin card.
_ANALYST_SUMMARY: dict[str, str] = {
    "forbidden": "The vendor accepts the credentials but refuses access to the data.",
    "auth": "The vendor rejected the stored credentials.",
    "transport": "The vendor could not be reached or answered unexpectedly; retrying automatically.",
    "internal": "The poll failed inside Athena; retrying automatically.",
}
_ANALYST_SUFFIX = " An administrator can see the details under Settings → Integrations."


def analyst_summary(instance_id: Optional[int]) -> str:
    """One fixed sentence for an instance whose row says 'error'."""
    kind = snapshot(instance_id)["failure_kind"]
    return _ANALYST_SUMMARY.get(kind or "", "Not working.") + _ANALYST_SUFFIX


# What a poller without vendor-specific guidance writes as the admin-visible
# detail. Platform-authored on purpose: some clients' error text quotes the
# vendor's response body, which never belongs on the card.
_POLL_FAILURE_DETAIL: dict[str, str] = {
    "forbidden": "{vendor} accepts the stored credentials but refuses access to "
                 "the data. Grant the API user access on the {vendor} side.",
    "auth": "{vendor} rejected the stored credentials. Check that the API user "
            "still exists and its key or password was not changed on the "
            "{vendor} side.",
    "transport": "Could not reach {vendor}, or it answered unexpectedly. The "
                 "server log has the technical detail.",
    "internal": "The {vendor} poll failed inside Athena ({error}); see the "
                "server log.",
}
_POLL_RETRY_NOTE = (
    " Athena keeps retrying on its own; this clears as soon as a poll succeeds."
)


def poll_failure_detail(
    vendor: str, kind: FailureKind, exc: Optional[BaseException] = None,
) -> str:
    """The detail for a failed poll, built from fixed sentences — only the
    exception's CLASS name is used (for 'internal'), never its text."""
    template = _POLL_FAILURE_DETAIL.get(kind, _POLL_FAILURE_DETAIL["internal"])
    error = type(exc).__name__ if exc is not None else "error"
    return template.format(vendor=vendor, error=error) + _POLL_RETRY_NOTE


def reset(instance_id: Optional[int] = None) -> None:
    """Forget one instance's contact state (on disable) or all of it (tests)."""
    with _lock:
        if instance_id is None:
            _contacts.clear()
        else:
            _contacts.pop(instance_id, None)


def _bounded(detail: str) -> str:
    flat = " ".join(
        "".join(c if c.isprintable() else " " for c in str(detail)).split()
    )
    if len(flat) > MAX_DETAIL_CHARS:
        flat = flat[: MAX_DETAIL_CHARS - 1].rstrip() + "…"
    return flat


def _write_contact_status(instance_id: int, status: str, detail: str) -> None:
    from apps.octo.instances.manager import set_contact_status

    set_contact_status(instance_id, status=status, status_detail=detail)


class ContactReporter:
    """One per running poller. Not thread-safe across callers — a poller
    reports sequentially from its own loop."""

    def __init__(
        self,
        instance_id: Optional[int],
        *,
        what: str,
        writer: Callable[[int, str, str], None] = _write_contact_status,
    ) -> None:
        self._instance_id = instance_id
        self._what = what
        self._writer = writer
        # What the row currently says, as far as this reporter knows. None
        # until the first report, so the first outcome after start is always
        # written (the manager's 'started' is a claim, not an observation).
        self._written: Optional[tuple[str, str]] = None

    def ok(self) -> None:
        now = utcnow_iso()
        if self._instance_id is not None:
            with _lock:
                entry = _contacts.setdefault(self._instance_id, _Contact())
                entry.last_ok_at = now
                entry.failure_kind = None
                entry.consecutive_failures = 0
                entry.failing_since = None
        self._transition("running", OK_DETAIL)

    def failed(self, kind: FailureKind, detail: str) -> None:
        now = utcnow_iso()
        if self._instance_id is not None:
            with _lock:
                entry = _contacts.setdefault(self._instance_id, _Contact())
                entry.last_failed_at = now
                entry.failure_kind = kind
                entry.consecutive_failures += 1
                if entry.failing_since is None:
                    entry.failing_since = now
        self._transition("error", _bounded(detail))

    def throttled(self, detail: str) -> None:
        """The vendor is rate limiting: calls wait, nothing failed. The row
        stays 'running' with the operator-visible `detail` (never 'error' —
        a throttle is not a broken integration)."""
        now = utcnow_iso()
        if self._instance_id is not None:
            with _lock:
                entry = _contacts.setdefault(self._instance_id, _Contact())
                entry.last_throttled_at = now
        self._transition("running", _bounded(detail))

    def _transition(self, status: str, detail: str) -> None:
        if self._instance_id is None or self._written == (status, detail):
            return
        try:
            self._writer(self._instance_id, status, detail)
        except Exception as exc:  # noqa: BLE001 — never break the poll loop
            # Not recorded as written, so the next report tries again.
            logger.error(
                "[%s] could not record instance id=%s status=%s (%s)",
                self._what, self._instance_id, status, type(exc).__name__,
            )
            return
        self._written = (status, detail)
        logger.log(
            logging.INFO if status == "running" else logging.WARNING,
            "[%s] instance id=%s is now %s: %s",
            self._what, self._instance_id, status, detail,
        )


class FailureBackoff:
    """Bounded exponential delay for failures that will not fix themselves.

    `next()` yields base, base·factor, … capped at `ceiling`; `reset()` on
    the first success. It only ever answers "how long to wait" — the caller's
    loop keeps running, so a permission fixed on the vendor side is picked up
    within one ceiling without a restart.
    """

    def __init__(
        self, *, base_sec: float = 60.0, ceiling_sec: float = 300.0, factor: float = 2.0,
    ) -> None:
        self._base = max(0.0, float(base_sec))
        self._ceiling = max(self._base, float(ceiling_sec))
        self._factor = max(1.0, float(factor))
        self._failures = 0

    @property
    def ceiling_sec(self) -> float:
        return self._ceiling

    def next(self) -> float:
        # Exponent capped so a key left forbidden for months cannot overflow.
        delay = self._base * (self._factor ** min(self._failures, 32))
        self._failures += 1
        return min(self._ceiling, delay)

    def reset(self) -> None:
        self._failures = 0
