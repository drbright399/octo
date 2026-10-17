"""Adapter lifecycle state machine.

Per ADR-005 §`Lifecycle states`. Five states with strict transition rules:

  REGISTERED → CONFIGURED → ACTIVE ↔ PAUSED → REMOVED

REGISTERED is the static class-discovered state (adapter code present, no
operator action). Operators progress an INSTANCE through CONFIGURED → ACTIVE
via the wizard. ACTIVE ↔ PAUSED is the runtime cycle. REMOVED is terminal
for that instance (creating a new instance starts fresh from CONFIGURED).
"""

from __future__ import annotations

from enum import Enum


class AdapterLifecycleState(str, Enum):
    """Per ADR-005 §`Lifecycle states`.

    String-valued enum so audit log entries serialize cleanly + state can
    be persisted as TEXT in SQLite.
    """

    REGISTERED = "registered"
    """Adapter class is discovered and present in the registry. No operator
    action yet. Visible in the wizard's 'Available adapters' list."""

    CONFIGURED = "configured"
    """Operator has completed the wizard for an instance. Credentials vaulted;
    tenant mapping exists. Not yet ingesting events."""

    ACTIVE = "active"
    """Smoke test passed; operator clicked 'go live'. Adapter is ingesting
    events for one or more tenants. Widget visible on dashboards."""

    PAUSED = "paused"
    """Operator paused (or auto-pause on health failure). Not ingesting; widget
    shows 'paused' state with last-known data; credentials preserved for resume."""

    REMOVED = "removed"
    """Instance deleted. Credentials shredded (per credential rules — verify
    durable storage first). Widget disappears; per-source events retained per
    per-row retention rules. Terminal state for THIS instance; a new instance
    can be created from REGISTERED state for the same adapter+tenant."""


class StateTransitionError(Exception):
    """Raised when a lifecycle transition is invalid.

    Carries the from/to states for audit-log correlation.
    """

    def __init__(
        self,
        from_state: AdapterLifecycleState,
        to_state: AdapterLifecycleState,
        message: str = "",
    ) -> None:
        msg = (
            f"Invalid transition {from_state.value} → {to_state.value}"
            + (f": {message}" if message else "")
        )
        super().__init__(msg)
        self.from_state = from_state
        self.to_state = to_state


# Valid transitions per ADR-005 §`Lifecycle states` diagram.
# Keys are FROM state; values are the set of allowed TO states.
_VALID_TRANSITIONS: dict[AdapterLifecycleState, frozenset[AdapterLifecycleState]] = {
    AdapterLifecycleState.REGISTERED: frozenset({
        AdapterLifecycleState.CONFIGURED,
    }),
    AdapterLifecycleState.CONFIGURED: frozenset({
        AdapterLifecycleState.ACTIVE,
        AdapterLifecycleState.REMOVED,
    }),
    AdapterLifecycleState.ACTIVE: frozenset({
        AdapterLifecycleState.PAUSED,
        AdapterLifecycleState.REMOVED,
    }),
    AdapterLifecycleState.PAUSED: frozenset({
        AdapterLifecycleState.ACTIVE,
        AdapterLifecycleState.REMOVED,
    }),
    AdapterLifecycleState.REMOVED: frozenset(),  # Terminal
}


def is_valid_transition(
    from_state: AdapterLifecycleState,
    to_state: AdapterLifecycleState,
) -> bool:
    """Check whether the transition is allowed by the state machine."""
    return to_state in _VALID_TRANSITIONS.get(from_state, frozenset())


def assert_valid_transition(
    from_state: AdapterLifecycleState,
    to_state: AdapterLifecycleState,
    reason: str = "",
) -> None:
    """Raise StateTransitionError if the transition is invalid."""
    if not is_valid_transition(from_state, to_state):
        raise StateTransitionError(from_state, to_state, reason)
