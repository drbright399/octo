"""OCTO framework runtime.

Per ADR-005 + ADR-006 (adapter contract, widget framework), this package
implements the runtime that hosts source-adapter instances + the bridge
contract surface inside the `octo-core` Docker container.

Modules:
- `registry` — adapter registry with lifecycle state machine + listener pubsub
- `lifecycle` — adapter state machine + transition rules
- `bridge_server` — BridgeServer Protocol impl with invariant enforcement +
  audit log; per-request executor pluggable via TemplateExecutor
- `discovery` — discovers SourceAdapter implementations in apps/octo/adapters/
"""

from apps.octo.framework.bridge_router import (
    BearerTokenResolver,
    StaticTokenResolver,
    create_bridge_router,
)
from apps.octo.framework.bridge_server import (
    AlwaysValidSessionValidator,
    AuditLogBackend,
    BridgeServerImpl,
    InMemoryAuditLogBackend,
    SessionValidator,
    TemplateExecutor,
)
from apps.octo.framework.discovery import (
    DiscoveryReport,
    discover_adapters,
    discover_adapters_from_path,
)
from apps.octo.framework.lifecycle import (
    AdapterLifecycleState,
    StateTransitionError,
    is_valid_transition,
)
from apps.octo.framework.registry import (
    AdapterInstance,
    AdapterRegistry,
    InMemoryRegistryBackend,
    RegistryBackend,
    StateChangeEvent,
    StateChangeListener,
)
from apps.octo.framework.sqlite_audit import (
    GENESIS_PREV_HASH,
    SCHEMA_VERSION as AUDIT_SCHEMA_VERSION,
    SqliteAuditLogBackend,
)
from apps.octo.framework.sqlite_registry import (
    SCHEMA_VERSION as REGISTRY_SCHEMA_VERSION,
    SqliteRegistryBackend,
)

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "AdapterInstance",
    "AdapterLifecycleState",
    "AdapterRegistry",
    "AlwaysValidSessionValidator",
    "AuditLogBackend",
    "BearerTokenResolver",
    "BridgeServerImpl",
    "DiscoveryReport",
    "GENESIS_PREV_HASH",
    "InMemoryAuditLogBackend",
    "InMemoryRegistryBackend",
    "REGISTRY_SCHEMA_VERSION",
    "RegistryBackend",
    "SessionValidator",
    "SqliteAuditLogBackend",
    "SqliteRegistryBackend",
    "StateChangeEvent",
    "StateChangeListener",
    "StateTransitionError",
    "StaticTokenResolver",
    "TemplateExecutor",
    "create_bridge_router",
    "discover_adapters",
    "discover_adapters_from_path",
    "is_valid_transition",
]
