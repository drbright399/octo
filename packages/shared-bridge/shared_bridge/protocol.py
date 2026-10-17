"""BridgeClient + BridgeServer Protocols.

Per ADR-004. Two sides of the bridge contract:
- BridgeClient: implemented in Athena Console; calls templates over the
  Docker-internal network to OCTO.
- BridgeServer: implemented in OCTO core; validates invariants + executes
  templates + writes audit log.

Both Protocols use PEP 544 for the same reason as the adapter contract:
implementations don't need to inherit from a framework class.
"""

from __future__ import annotations

from typing import Any, Protocol

from shared_bridge.types import AuditLogEntry, QueryResult, SessionContext


class BridgeClient(Protocol):
    """Athena-side client. Calls bridge query templates over HTTP.

    Constructed at operator-session-start with a SessionContext bound to
    the operator's tenant. Per invariant 3, cannot be retargeted mid-session
    — operator must end the session and start a new one to switch tenants
    (super_admin cross-tenant access requires explicit fresh session).
    """

    session: SessionContext

    def execute(
        self,
        template_id: str,
        params: dict[str, Any],
    ) -> QueryResult:
        """Execute a registered query template against OCTO.

        Per invariants:
        1. template_id must be in the registry (server-side rejection if not)
        2. read credential is used (BridgeWriteCredential cannot call this)
        3. session.session_tenant is the implicit scope; server enforces
        4. Returns include audit_entry_id; server has logged the call
        5. If template is cross-tenant, output is sanitized per the template's
           response_schema (anonymized; opaque tenant hashes)
        """
        ...

    def health(self) -> dict[str, Any]:
        """Health check: bridge endpoint reachable, server responds."""
        ...


class BridgeServer(Protocol):
    """OCTO-side server. Validates invariants + executes templates.

    Implementation in `apps/octo/framework/bridge_server.py`. Adapters write
    via service-bound BridgeWriteCredentials (different code path); operator
    reads come through this server.
    """

    def validate_session(self, session: SessionContext) -> bool:
        """Verify the session credential is valid (not expired, not revoked).

        Returns True iff acceptable. Server MUST audit-log the validation
        attempt either way (invariant 4)."""
        ...

    def execute_template(
        self,
        session: SessionContext,
        template_id: str,
        params: dict[str, Any],
    ) -> QueryResult:
        """Execute a registered template under the given session.

        Per invariant 1: template_id must be registered.
        Per invariant 3: results filtered to session.session_tenant unless
            template explicitly opts out (requires_tenant_scope=False).
        Per invariant 4: audit log entry written before return.
        Per invariant 5: cross-tenant output sanitized if applicable.

        Raises InvariantViolation on any violation; server still audit-logs
        the rejection."""
        ...

    def get_audit_log(
        self,
        *,
        session_id: str | None = None,
        operator_id: int | None = None,
        tenant: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        """Operator-accessible read of the bridge audit log.

        Filtered by role at the implementation layer:
        - viewer/analyst: only their own session_id entries
        - admin: all entries within tenants they admin
        - super_admin: all entries
        """
        ...
