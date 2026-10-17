# shared-bridge

Versioned public bridge contract between Athena (control plane) and OCTO (data plane). Defines the closed-set query template registry, session-bound credential model, audit log schema, and runtime enforcement of the five mandatory invariants.

Per ADR-004 (bridge as a public, versioned interface) — a design note, not in this repository (index: `docs/adrs/README.md`); see `docs/architecture.md`. Sibling to ADR-003 (data/control-plane boundary discipline).

## Status

Bridge contract version: **1.0**

Phase 1b/2 deliverable from task #58 + task #64. The framework is the product, not the adapters: this contract is what makes the framework structurally enforceable rather than honor-system code discipline.

## Layout

```
shared-bridge/
├── pyproject.toml
├── shared_bridge/
│   ├── __init__.py                 public exports + BRIDGE_CONTRACT_VERSION
│   ├── types.py                    QueryTemplate, SessionContext,
│   │                                 BridgeReadCredential, BridgeWriteCredential,
│   │                                 AuditLogEntry, TemplateRegistry, QueryResult
│   ├── protocol.py                 BridgeClient + BridgeServer Protocols
│   ├── invariants.py               enforcement helpers (raise InvariantViolation)
│   └── templates/
│       └── __init__.py             template definitions land as adapters need them
├── tests/
│   └── test_invariants.py          12 tests across the 5 invariants
└── README.md
```

## The five mandatory invariants

Per ADR-004:

1. **Parameterized queries only.** `BridgeClient.execute(template_id, params)`. No raw SQL ever crosses the bridge. The set of `template_id` values is enumerated by the `TemplateRegistry` and bounded.

2. **Separate read/write credentials.** `BridgeReadCredential` (operator session reads) and `BridgeWriteCredential` (adapter ingest writes) are distinct types; conflation is structurally rejected at the server.

3. **Session-bound `tenant_id`.** `SessionContext.session_tenant` is fixed at session start; the client cannot retarget mid-session. The bridge server enforces this when a caller provides an explicit `requested_tenant` that differs from the session binding.

4. **Per-query audit log.** Every accepted query — and every rejected one — writes an `AuditLogEntry` with timestamp, operator, tenant, template_id, params hash (NOT values, to prevent side-channel leak), result row count, accepted flag, and rejection reason if applicable.

5. **Cross-tenant retrieval safety.** The sanitized pool's `tenant_hashes` field carries opaque hashes (sha256(slug || pepper)), never raw slugs. `validate_no_cross_tenant_leak()` enforces that cross-tenant templates' result rows don't contain `{tenant_slug, tenant_id, client_slug, client_id}` keys. Output filter applies before render in Athena Console.

## Why these invariants matter

Cross-tenant indirect prompt injection via the sanitized pool is the centerpiece risk (the sanitized-pool safety-envelope design note). The bridge contract is the structural mitigation:

- A prompt injection inside Athena's agent harness **cannot** make the bridge query a different tenant — the tenant binding is structural (invariant 3), not agent-asserted.
- A prompt injection **cannot** construct an arbitrary SQL query — the closed template registry (invariant 1) means no template_id outside the bounded set can execute.
- A prompt injection **cannot** exfiltrate raw tenant identifiers from the sanitized pool — the cross-tenant safety check (invariant 5) blocks it before render.
- Behavioral monitoring (invariant 4 audit log) catches anomalous query distributions across operator sessions.

## Install + run tests

```bash
cd packages
.venv/bin/pip install -e ./shared-bridge'[dev]'
.venv/bin/pytest shared-bridge/tests/ -v
```

## Cross-references

- `docs/architecture.md` — the Athena/OCTO boundary and the bridge this implements
- ADR-003..006 (boundary, bridge, adapter contract, widget framework) — design notes, not in this repository; indexed in `docs/adrs/README.md`
- `packages/shared-adapter-contract/` — adapters write through the bridge
- `packages/shared-widget-contract/` — widgets read through the bridge
- Bridge templates default-scope by `(session.operator_id, session.role)` for ownership-aware visibility
- Task #58 (extract packages/shared-bridge from OCTO code) — this delivers it
