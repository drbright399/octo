"""Adapter registry — tracks registered adapter classes + per-instance state.

Per ADR-005 (adapter contract). The registry is the source
of truth for:
- Which adapter classes are discovered + registered (REGISTERED state)
- Which (vendor × tenant × instance_id) combinations are CONFIGURED / ACTIVE / PAUSED / REMOVED
- Subscriber pub-sub for state-change events (widget registry depends on this)

Backend abstraction: `RegistryBackend` Protocol. In-memory implementation
ships for testing; production implementation persists to OCTO `registry.db`
(arrives in a later phase).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from shared_adapter_contract import SourceAdapter

from apps.octo.framework.lifecycle import (
    AdapterLifecycleState,
    assert_valid_transition,
)


# ---------------------------------------------------------------------------
# Adapter instance — one (vendor × tenant × instance_id) record
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AdapterInstance:
    """One configured deployment of an adapter for one tenant.

    A single adapter class (e.g., DattoRMMAdapter) can have many instances —
    one per tenant the MSP has connected to that vendor.
    """

    instance_key: str
    """Stable composite key: '<vendor_slug>:<tenant_slug>:<instance_id>'."""

    vendor_slug: str
    tenant_slug: str
    instance_id: str

    state: AdapterLifecycleState

    credentials_ref: str
    """Reference to the credential vault entry for this instance (e.g.,
    OpenBao path or per-MSP encrypted key kid). NEVER the actual credential."""

    tenant_mapping: dict[str, Any] = field(default_factory=dict)
    """Vendor-side tenant identifier(s) → OCTO slug. Free-form per vendor."""

    rate_limit_overrides: dict[str, Any] = field(default_factory=dict)
    """Per-instance overrides on the adapter's declared rate_limit_hints."""

    created_at: str = ""
    last_state_change_at: str = ""
    state_change_reason: str = ""
    """Operator-supplied or system reason for the most recent state transition.
    Audit-log substrate."""

    def with_state(
        self,
        new_state: AdapterLifecycleState,
        reason: str = "",
    ) -> AdapterInstance:
        """Return a new AdapterInstance with `state` advanced to new_state.

        Performs lifecycle validation; raises `StateTransitionError` on invalid
        transition. Frozen dataclass means original instance is unchanged.
        """
        assert_valid_transition(self.state, new_state, reason)
        return replace(
            self,
            state=new_state,
            last_state_change_at=_utc_iso_now(),
            state_change_reason=reason,
        )


# ---------------------------------------------------------------------------
# State-change event + listener types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StateChangeEvent:
    """Emitted whenever an adapter instance changes lifecycle state.

    Subscribers (widget registry, audit log writer, operator UI notifications)
    consume these via `AdapterRegistry.subscribe()`.
    """

    instance: AdapterInstance
    from_state: AdapterLifecycleState
    to_state: AdapterLifecycleState
    reason: str
    occurred_at: str
    """ISO8601 UTC."""


StateChangeListener = Callable[[StateChangeEvent], None]
"""Subscriber callable. Listeners should be fast — heavy work (audit writes,
network calls) happens elsewhere. Listeners that raise propagate the exception
to the caller (registry doesn't swallow listener errors)."""


# ---------------------------------------------------------------------------
# Backend Protocol
# ---------------------------------------------------------------------------

class RegistryBackend(Protocol):
    """Persistence backend for the adapter registry.

    In-memory implementation ships for testing. Production backend persists
    to OCTO registry.db with proper hash-chained audit per ADR-005 audit
    discipline.
    """

    def get_instance(self, instance_key: str) -> AdapterInstance | None:
        """Look up an instance by its composite key. None if not found."""
        ...

    def put_instance(self, instance: AdapterInstance) -> None:
        """Insert or update an instance. Idempotent — same input produces same state."""
        ...

    def list_instances(
        self,
        *,
        vendor_slug: str | None = None,
        tenant_slug: str | None = None,
        state: AdapterLifecycleState | None = None,
    ) -> list[AdapterInstance]:
        """List instances optionally filtered by vendor / tenant / state."""
        ...

    def delete_instance(self, instance_key: str) -> None:
        """Remove an instance from the backend. Use only after lifecycle-correct
        transition to REMOVED + credential shred."""
        ...


class InMemoryRegistryBackend:
    """In-memory backend. Suitable for tests + ephemeral runs.

    Production deployment uses a SQLite-backed implementation with proper
    audit chain — that ships in a later phase.
    """

    def __init__(self) -> None:
        self._instances: dict[str, AdapterInstance] = {}

    def get_instance(self, instance_key: str) -> AdapterInstance | None:
        return self._instances.get(instance_key)

    def put_instance(self, instance: AdapterInstance) -> None:
        self._instances[instance.instance_key] = instance

    def list_instances(
        self,
        *,
        vendor_slug: str | None = None,
        tenant_slug: str | None = None,
        state: AdapterLifecycleState | None = None,
    ) -> list[AdapterInstance]:
        results = list(self._instances.values())
        if vendor_slug is not None:
            results = [r for r in results if r.vendor_slug == vendor_slug]
        if tenant_slug is not None:
            results = [r for r in results if r.tenant_slug == tenant_slug]
        if state is not None:
            results = [r for r in results if r.state == state]
        return results

    def delete_instance(self, instance_key: str) -> None:
        self._instances.pop(instance_key, None)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class AdapterRegistry:
    """Tracks registered adapter classes + per-instance lifecycle state.

    Two layers:
    - Adapter classes (registered once at framework startup via discovery)
    - Adapter instances (per (vendor × tenant × instance_id) — created/managed
      via the operator wizard)

    Listeners subscribe via `subscribe()` and receive `StateChangeEvent`s on
    every instance state transition.
    """

    def __init__(self, backend: RegistryBackend | None = None) -> None:
        self._backend: RegistryBackend = backend or InMemoryRegistryBackend()
        self._adapter_classes: dict[str, type[SourceAdapter]] = {}
        self._listeners: list[StateChangeListener] = []

    # --- Adapter class registration ---

    def register_adapter_class(self, adapter_cls: type[SourceAdapter]) -> None:
        """Register an adapter class (REGISTERED state — class-level).

        Idempotent: re-registering the same class with the same vendor_slug
        is a no-op. Registering a different class with an existing vendor_slug
        raises ValueError.
        """
        slug = adapter_cls.vendor_slug
        existing = self._adapter_classes.get(slug)
        if existing is not None and existing is not adapter_cls:
            msg = (
                f"vendor_slug='{slug}' already registered to a different class "
                f"({existing.__name__}); cannot replace with {adapter_cls.__name__}"
            )
            raise ValueError(msg)
        self._adapter_classes[slug] = adapter_cls

    def get_adapter_class(self, vendor_slug: str) -> type[SourceAdapter] | None:
        return self._adapter_classes.get(vendor_slug)

    def list_adapter_classes(self) -> list[type[SourceAdapter]]:
        return list(self._adapter_classes.values())

    # --- Instance lifecycle ---

    def configure_instance(
        self,
        *,
        vendor_slug: str,
        tenant_slug: str,
        instance_id: str,
        credentials_ref: str,
        tenant_mapping: dict[str, Any] | None = None,
        rate_limit_overrides: dict[str, Any] | None = None,
        reason: str = "wizard onboarding",
    ) -> AdapterInstance:
        """Create a CONFIGURED instance (REGISTERED → CONFIGURED).

        Raises ValueError if vendor_slug isn't registered as an adapter class
        or if the (vendor × tenant × instance_id) tuple already exists.
        """
        if vendor_slug not in self._adapter_classes:
            msg = f"vendor_slug='{vendor_slug}' not registered as an adapter class"
            raise ValueError(msg)

        instance_key = _make_instance_key(vendor_slug, tenant_slug, instance_id)
        existing = self._backend.get_instance(instance_key)
        if existing is not None and existing.state != AdapterLifecycleState.REMOVED:
            msg = (
                f"Instance '{instance_key}' already exists in state "
                f"{existing.state.value}; cannot re-configure"
            )
            raise ValueError(msg)

        now = _utc_iso_now()
        instance = AdapterInstance(
            instance_key=instance_key,
            vendor_slug=vendor_slug,
            tenant_slug=tenant_slug,
            instance_id=instance_id,
            state=AdapterLifecycleState.CONFIGURED,
            credentials_ref=credentials_ref,
            tenant_mapping=tenant_mapping or {},
            rate_limit_overrides=rate_limit_overrides or {},
            created_at=now,
            last_state_change_at=now,
            state_change_reason=reason,
        )
        self._backend.put_instance(instance)

        self._emit(StateChangeEvent(
            instance=instance,
            from_state=AdapterLifecycleState.REGISTERED,
            to_state=AdapterLifecycleState.CONFIGURED,
            reason=reason,
            occurred_at=now,
        ))
        return instance

    def transition(
        self,
        instance_key: str,
        *,
        to_state: AdapterLifecycleState,
        reason: str,
    ) -> AdapterInstance:
        """Transition an existing instance to a new state.

        Raises KeyError if instance doesn't exist; StateTransitionError if
        the transition is invalid per the lifecycle state machine.
        """
        existing = self._backend.get_instance(instance_key)
        if existing is None:
            msg = f"Instance '{instance_key}' not found"
            raise KeyError(msg)

        from_state = existing.state
        new_instance = existing.with_state(to_state, reason=reason)
        self._backend.put_instance(new_instance)

        self._emit(StateChangeEvent(
            instance=new_instance,
            from_state=from_state,
            to_state=to_state,
            reason=reason,
            occurred_at=new_instance.last_state_change_at,
        ))
        return new_instance

    # Convenience wrappers for the typical state moves
    def activate(self, instance_key: str, reason: str = "operator go-live") -> AdapterInstance:
        return self.transition(instance_key, to_state=AdapterLifecycleState.ACTIVE, reason=reason)

    def pause(self, instance_key: str, reason: str) -> AdapterInstance:
        return self.transition(instance_key, to_state=AdapterLifecycleState.PAUSED, reason=reason)

    def resume(self, instance_key: str, reason: str = "operator resume") -> AdapterInstance:
        return self.transition(instance_key, to_state=AdapterLifecycleState.ACTIVE, reason=reason)

    def remove(self, instance_key: str, reason: str) -> AdapterInstance:
        return self.transition(instance_key, to_state=AdapterLifecycleState.REMOVED, reason=reason)

    # --- Lookup ---

    def get_instance(self, instance_key: str) -> AdapterInstance | None:
        return self._backend.get_instance(instance_key)

    def list_instances(
        self,
        *,
        vendor_slug: str | None = None,
        tenant_slug: str | None = None,
        state: AdapterLifecycleState | None = None,
    ) -> list[AdapterInstance]:
        return self._backend.list_instances(
            vendor_slug=vendor_slug, tenant_slug=tenant_slug, state=state,
        )

    def list_active(self, *, tenant_slug: str | None = None) -> list[AdapterInstance]:
        """Convenience: all instances currently in ACTIVE state."""
        return self.list_instances(
            tenant_slug=tenant_slug, state=AdapterLifecycleState.ACTIVE,
        )

    # --- Subscription ---

    def subscribe(self, listener: StateChangeListener) -> None:
        """Register a listener for state-change events. Idempotent (same listener
        added twice still only receives one notification per event)."""
        if listener not in self._listeners:
            self._listeners.append(listener)

    def unsubscribe(self, listener: StateChangeListener) -> None:
        """Remove a previously-subscribed listener. No-op if not subscribed."""
        if listener in self._listeners:
            self._listeners.remove(listener)

    def _emit(self, event: StateChangeEvent) -> None:
        """Fan out a state-change event to all subscribers.

        Listener exceptions propagate — registry does not swallow them.
        Subscribers that need fault tolerance must wrap their own try/except.
        """
        for listener in self._listeners:
            listener(event)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_instance_key(vendor_slug: str, tenant_slug: str, instance_id: str) -> str:
    return f"{vendor_slug}:{tenant_slug}:{instance_id}"


def _utc_iso_now() -> str:
    """ISO8601 UTC with millisecond precision + Z suffix (matches CanonicalEvent)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
