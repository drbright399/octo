"""Versioned public bridge contract between Athena and OCTO.

Per design note ADR-004 (kept outside this repository; index:
`docs/adrs/README.md`), this package defines the contract that connects
Athena's control plane to OCTO's data plane. Five mandatory invariants every
implementation must honor:

1. Parameterized queries only (closed-set template registry; no raw SQL)
2. Separate read/write credentials (different env vars; conflation rejected)
3. Session-bound tenant_id (cannot retarget mid-session)
4. Per-query audit log (every accepted query logged)
5. Cross-tenant retrieval safety (sanitized pool only via dedicated template;
   output filter checks for tenant identifier leakage)

Stable contract version: 1.0
"""

from shared_bridge.invariants import (
    InvariantViolation,
    enforce_session_tenant_match,
    enforce_template_registered,
    validate_no_cross_tenant_leak,
)
from shared_bridge.protocol import BridgeClient, BridgeServer
from shared_bridge.types import (
    AuditLogEntry,
    BridgeAuthMode,
    BridgeReadCredential,
    BridgeWriteCredential,
    QueryTemplate,
    QueryResult,
    SessionContext,
    TemplateRegistry,
)

BRIDGE_CONTRACT_VERSION = "1.0"

__all__ = [
    "BRIDGE_CONTRACT_VERSION",
    "AuditLogEntry",
    "BridgeAuthMode",
    "BridgeClient",
    "BridgeReadCredential",
    "BridgeServer",
    "BridgeWriteCredential",
    "InvariantViolation",
    "QueryResult",
    "QueryTemplate",
    "SessionContext",
    "TemplateRegistry",
    "enforce_session_tenant_match",
    "enforce_template_registered",
    "validate_no_cross_tenant_leak",
]
