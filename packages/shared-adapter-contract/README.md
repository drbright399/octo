# shared-adapter-contract

Source-adapter contract for the Athena/OCTO framework. Defines the abstract `SourceAdapter` Protocol every adapter implements, plus the canonical event shape, onboarding declarations, and widget reference type.

Per ADR-005 (adapter contract) — a design note, not in this repository (index: `docs/adrs/README.md`).

## Status

Contract version: **1.0**

Phase 1a deliverable from task #64. Sibling to `shared-widget-contract` (full widget contract per ADR-006) and `shared-bridge` (bridge contract per ADR-004).

## Layout

```
shared-adapter-contract/
├── pyproject.toml                       editable install + ruff + mypy + pytest config
├── shared_adapter_contract/
│   ├── __init__.py                      public exports + CONTRACT_VERSION
│   ├── types.py                         frozen dataclasses for CanonicalEvent,
│   │                                     CredentialField, TenantMappingShape, etc.
│   ├── protocol.py                      SourceAdapter Protocol (PEP 544)
│   └── base.py                          BaseSourceAdapter ABC with sensible defaults
├── tests/
│   └── test_protocol.py                 conformance + determinism + immutability tests
└── README.md
```

## Install (editable, for development)

```bash
cd packages/shared-adapter-contract
pip install -e '.[dev]'
```

## Run tests

```bash
pytest tests/ -v
```

## Two ways to implement an adapter

### 1. `BaseSourceAdapter` ABC (convenient)

Inherit + override the abstract methods. Lifecycle hooks (`start`, `stop`, `health`) and `widget_definition`, `rate_limit_hints` have sensible defaults.

```python
from shared_adapter_contract import BaseSourceAdapter, CanonicalEvent, ...

class DattoRMMAdapter(BaseSourceAdapter):
    vendor_slug = "datto-rmm"
    vendor_display_name = "Datto RMM"
    vendor_logo_path = "/logos/datto-rmm.svg"
    auth_model = "oauth2"
    delivery_mode = "hybrid"
    compliance_categories = ["hipaa-friendly", "general"]

    def credential_shape(self): ...
    def extract_event(self, raw_envelope): ...
    # ... etc.
```

### 2. `SourceAdapter` Protocol (maximum flexibility)

Implement the Protocol directly without inheriting. Useful when an adapter needs deep customization or already has its own base class.

```python
from shared_adapter_contract import SourceAdapter

class CustomAdapter:  # implicitly satisfies SourceAdapter Protocol
    vendor_slug = "custom"
    # ... all required attrs + methods ...
```

The framework treats both equivalently — Protocol conformance is what matters, not inheritance.

## What this package does NOT contain

- **WidgetDefinition full type** — lives in `shared_widget_contract` per ADR-006. This package exposes `WidgetDefinitionRef` (just the widget_id) since adapters return references that the framework resolves at registry-build time.
- **Bridge contract types** — live in `shared_bridge` per ADR-004. Adapters write data through the bridge but don't construct bridge query templates.
- **Framework runtime** — discovery, registry, lifecycle plumbing live in `apps/octo/framework/`. This package is contract-only.

## Cross-references

- `docs/architecture.md` — the Athena/OCTO boundary this implements
- ADR-003..006 (boundary, bridge, adapter contract, widget framework) — design notes, not in this repository; indexed in `docs/adrs/README.md`
- `packages/shared-widget-contract/` — the sibling widget framework
- `packages/shared-bridge/` — bridge contract (sibling)
- Vendor neutrality: the framework is the product, not the adapters, and no vendor is privileged
