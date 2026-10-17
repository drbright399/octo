"""Autotask PSA → OCTO adapter (P4 — first PSA adapter).

Per the Autotask round-trip research + the Option C MCP-at-the-
boundary decision (2026-05-14), this adapter:

  - lives flat alongside the other OCTO source-adapters (datto,
    rocketcyber, unifi, wazuh) for AdapterRegistry-discovery
    convenience. The PsaAdapter abstraction is extracted when the
    SECOND PSA adapter (ConnectWise / HaloPSA) lands — pull the
    abstraction when there's a real second concrete to compare against,
    not before.
  - is built REST-first so the audit + RBAC chains stay under our
    control (non-negotiable per the noise-dismissal north-star).
  - will gain a sibling MCP wrapper at `apps/octo/adapters/autotask_mcp/`
    when the agent runtime (#119) actually needs to consume MCP. For
    now the adapter is REST-only.

P4-a scope (this commit): zone resolution + health check + credential
shape + tenant mapping declaration + smoke-test. NO polling, NO writes
yet — those land in P4-c1 and P4-c2 respectively.

The actual ticket-data ingest is bidirectional (read AND write) so the
adapter is registered as a SourceAdapter for the read-only ingest path
(Phase A, P4-c1), and a separate outbound queue + worker handles writes
(Phase B, P4-c2). The two share this same `AutotaskClient` for HTTP +
auth.
"""
from apps.octo.adapters.autotask.adapter import AutotaskSourceAdapter
from apps.octo.adapters.autotask.client import (
    AutotaskAuthError,
    AutotaskClient,
    AutotaskClientError,
    AutotaskConfig,
    AutotaskRefusedError,
    AutotaskZoneError,
    resolve_zone,
)

# Re-export trick: the framework's discovery walker only finds classes
# whose __module__ matches the scanned package. Adapter classes live
# in submodules but get re-exported here; rewriting __module__ lets
# discovery see this class without scanning every submodule recursively.
# (Same approach used by datto + wazuh — see their __init__.py.)
AutotaskSourceAdapter.__module__ = "apps.octo.adapters.autotask"

__all__ = [
    "AutotaskAuthError",
    "AutotaskClient",
    "AutotaskClientError",
    "AutotaskConfig",
    "AutotaskRefusedError",
    "AutotaskSourceAdapter",
    "AutotaskZoneError",
    "resolve_zone",
]
