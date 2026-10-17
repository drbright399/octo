# shared-widget-contract

Widget framework contract for Athena Console. Defines the full `WidgetDefinition`, the registry-side `RegisteredWidget` + `WidgetRegistry` Protocol, layout persistence shapes, and the canonical default render component IDs.

Per ADR-006 (widget framework) — a design note, not in this repository (index: `docs/adrs/README.md`). Sibling to `shared-adapter-contract` (per ADR-005).

## Status

Widget contract version: **1.0**

Phase 1b deliverable from task #64.

## Layout

```
shared-widget-contract/
├── pyproject.toml
├── shared_widget_contract/
│   ├── __init__.py                 public exports + WIDGET_CONTRACT_VERSION
│   ├── types.py                    WidgetDefinition + ConfigurableParam +
│   │                                 DEFAULT_RENDER_COMPONENTS
│   ├── registry.py                 RegisteredWidget + WidgetRegistry Protocol +
│   │                                 WidgetSource
│   └── layout.py                   LayoutGrid + LayoutItem + LayoutPosition +
│                                     LayoutSize (per-operator persistence shapes)
├── tests/
│   └── test_widget_contract.py     conformance + immutability + floor-validation
└── README.md
```

## Two widget types, one framework

Per ADR-006 §`Widget Registry`:

- **Adapter widgets** — declared by a `SourceAdapter` via `widget_definition()`. Lifecycle derived from adapter state (auto-add when adapter ACTIVE; auto-remove when REMOVED).
- **System widgets** — ship with the framework (Findings Queue, Threat Intel Pulse, Audit Status, etc.). Always available; operator can show/hide.

Both types use the same `WidgetDefinition` shape; UI doesn't distinguish at render time.

## The five default render components

The framework ships 5 canonical render components most adapter widgets reuse:

| component_ref | typical use | data shape |
|---|---|---|
| `default-alert-feed` | live alert feed (clickable rows → vendor deep-link) | `list[CanonicalEvent]` |
| `default-counter-grid` | stat tiles (totals, by-severity, by-source) | `dict[str, int]` |
| `default-time-series` | line/bar chart of events over time | `list[(timestamp, count)]` |
| `default-list-with-actions` | generic list + operator-clickable rows | `list[dict]` + handlers |
| `default-status-panel` | health status with traffic-light indicators | `{status, message, ...}` |

Custom components for visualization-heavy adapters (e.g., `buoy.fleet-flowmap`, `unifi.network-topology`) follow the convention `<vendor_slug>.<component>`.

## What this package does NOT contain

- **Render component implementations** — those live in `apps/athena/widgets/components/` (React + TypeScript)
- **WidgetRegistry runtime** — implementation in `apps/athena/framework/widget_registry.py`
- **Layout migration logic** — when an operator's saved layout references a no-longer-registered widget; lives in `apps/athena/framework/layout_migration.py`
- **Role-default JSON files** — ship in `apps/athena/widgets/role_defaults/` (super_admin / admin / analyst / viewer starting layouts)

## Cross-references

- `docs/architecture.md` — widgets live in Athena Console (single UI)
- `packages/shared-adapter-contract/` — adapter contract (sibling); adapters reference widgets via `WidgetDefinitionRef`
- `packages/shared-bridge/` — the bridge templates widgets call into apply ownership scoping
- ADR-005/006 (adapter contract, widget framework) — design notes, not in this repository; indexed in `docs/adrs/README.md`
- Widgets inherit the console's light-theme calibration
