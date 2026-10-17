# Architecture

> **2026-09-09 — read ADR-0002 first** (`docs/adrs/0002-octo-data-substrate.md`).
> The control-plane *orchestrator* described below is not built as product
> code; the operator AI fills that role on demand, consuming OCTO as its data
> substrate (MCP + note write-back + daily watch). The console, bridge
> invariants, and data-plane description below remain accurate.

Athena/OCTO is a two-service platform that separates **control plane**
from **data plane** behind a small, audited bridge.

## Two halves

### Athena — the control plane

What operators see and use. Hosts the operator console (Vite/React),
the layout + widget framework, ticket and finding workflows, and the
outbound action-adapter surface (e.g., device isolation, ticketing).

Lives in `apps/athena/`:

- `framework/` — Python: layout service (per-operator persistence),
  widget registry client, framework boot (discovery + registration of
  system widgets and adapter widgets).
- `widgets/components/` — TSX render components (alert-feed,
  counter-grid, status-panel, time-series, list-with-actions,
  attention-rotator). Each is a "dumb" component: typed rows in,
  rendered output out, no fetching.
- `web/` — Vite + React + TS app. Topbar + sidebar + dashboard with a
  hero panel and secondary widget grid. Hash-routed pages
  (`/dashboard`, `/tickets`, `/fleet`, `/settings`).

### OCTO — the data plane

Where tenant data lives. Hosts the source-adapter registry, the bridge
server, the hash-chained audit log, and the per-source query template
executor. Speaks HTTP to Athena over a typed bridge.

Lives in `apps/octo/`:

- `framework/` — Python: registries (in-memory + SQLite backends), the
  bridge server with five invariants, the audit log with hash chain,
  the template executor placeholder.
- `adapters/` — drop-in source adapters. Each adapter package
  declares what it ingests and what widgets it provides; the framework
  discovers them at boot.
- `main.py` + `Dockerfile` — FastAPI entrypoint, container image.

## The bridge

A small HTTP surface (`/bridge/v1/*`) that Athena calls into to read
data. It enforces five invariants:

1. **Closed template set.** Only registered query templates can run.
   No ad-hoc SQL from the control plane.
2. **Session-bound tenant.** Every query carries a session whose
   tenant scope is checked against the template's allowed scopes.
3. **Hash-chained audit log.** Every accepted query writes an entry;
   each entry's hash includes the prior entry's hash. Tampering with
   one row breaks the chain forward.
4. **Structured query results.** Templates return `QueryResult` with
   typed rows + an `audit_entry_id` reference, never raw cursors.
5. **Single point of control.** The bridge is the only path between
   the two halves. No app-level shortcuts.

Code: `packages/shared-bridge/shared_bridge/invariants.py`.

## Shared contract packages

`packages/shared-*/` are dependency-free Python packages that define
the Protocols both halves depend on. Athena and OCTO import them
without depending on each other.

- `shared-adapter-contract/` — Adapter Protocol, lifecycle states,
  source-adapter base.
- `shared-widget-contract/` — Widget Protocol, layout types, the five
  default render components.
- `shared-bridge/` — Bridge Protocol, invariants, audit log shape,
  query template type.

Mirrored on the TS side at
`apps/athena/web/src/contracts/{widget,alert,integration}.ts`. Drift
between Python and TS is caught manually today; a contract-snapshot
test will land with the bridge wiring.

## Data isolation

- Per-tenant SQLite files (one DB per client per artifact). Lookups
  scope by file path, not by `WHERE tenant_id = …`. Cross-tenant leak
  via "wrong tenant_id" is impossible because the wrong file is
  literally not opened.
- Audit log is hash-chained, retained at CJIS-grade duration (~10y).
  Operational events (alerts, findings) retained ~30d uniform.

## Frontend stack

- Vite 6 + React 19 + TypeScript (strict, with
  `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`).
- Tailwind 3 with semantic tokens that map to CSS variables; the
  light/dark theme switch flips `data-theme` on `<html>` without
  re-rendering React.
- Vitest + Testing Library for component tests.
- Hash-based router (no `react-router` dep — the surface is small
  enough to own in-house).

## What's not here yet

- **Real bridge wiring from frontend to backend.** Today the Vite app
  uses synthetic mock data in `apps/athena/web/src/mock/`. The next
  sprint replaces the mock layer with bridge-client fetches; the API
  shape is already defined in `apps/athena/web/src/lib/api.ts` with a
  `USE_MOCK = true` flag.
- **Real query routing in `TemplateExecutor`.** The Phase G.2 sprint
  lands per-tenant DB routing.
- **WORM verifier + CI gate** for the audit hash chain.
- **Athena container Dockerfile.** Only OCTO is Dockerized today.

## Where to look first

- New to the codebase? `docs/CLAUDE-ONBOARDING.md` is a Claude-agent
  guide that doubles as a fast human onboarding doc.
- Adding an API route? `docs/audit-policy.md` says whether it writes an
  audit row per call, rolls up, or is not audited.
- Deploying or upgrading the bundle? `docs/operations/bundle.md`.
- Adding a render component? Read one of the existing files in
  `apps/athena/widgets/components/` and copy the pattern.
- Adding a source adapter? Start with the Protocol in
  `packages/shared-adapter-contract/shared_adapter_contract/protocol.py`.
- Confused about why something is shaped a certain way? The contract
  packages have docstrings explaining the *why*; ADRs live in
  `docs/adrs/` (see `docs/adrs/README.md` for the index and for the
  three-digit design notes code comments cite).
