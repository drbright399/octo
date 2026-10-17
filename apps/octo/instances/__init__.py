"""Adapter instance manager — boot-time orchestration of persisted
adapter instances.

Distinct from `apps.octo.framework.registry.AdapterRegistry`, which tracks
adapter CLASSES + per-tenant lifecycle state. The InstanceManager is the
runtime owner of the persisted upstream configs stored in
`registry.db.adapter_instances` (migration 007). It:

- Reads rows from `adapter_instances`
- Decrypts credentials via `apps.octo.credentials.load(cred_ref)`
- Calls each adapter's `start(instance_config)` to spawn its poller
- Tracks the live adapter object so `stop_instance()` can call back

One adapter row → one upstream connection → many CanonicalEvents fanning
out to multiple OCTO clients via the adapter's own `route_to_tenant()`.
"""
from __future__ import annotations

from apps.octo.instances.manager import (
    InstanceLifecycleError,
    InstanceManager,
    InstanceRecord,
    create_instance,
    list_instances,
    update_instance_status,
)

__all__ = [
    "InstanceLifecycleError",
    "InstanceManager",
    "InstanceRecord",
    "create_instance",
    "list_instances",
    "update_instance_status",
]
