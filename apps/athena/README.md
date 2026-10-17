# Athena — operator-facing app

Athena is the operator-facing half of the Athena/OCTO bundle. OCTO
owns the data plane (`apps/octo/`); Athena owns presentation +
operator orchestration.

## Directory layout

| Subdirectory | Language | Purpose |
|--------------|----------|---------|
| `web/` | TypeScript / React | The Athena Console SPA — single operator UI, see `web/README.md` |
| `framework/` | Python | Layouts, widget registry client, boot orchestration |
| `widgets/` | Python | Backend widget contracts (the system bundle lives here) |
| `adapters/` | Python | Outbound action-adapter framework (the Athena counterpart to OCTO's source-adapter framework) |

## Where Athena talks to OCTO

All cross-boundary calls go through OCTO's bridge endpoints under
`/api/v1/*`. The bridge contract — Athena requesting, OCTO
authorizing + executing — is documented in
`docs/architecture.md` § The bridge and `packages/shared-bridge/` (the
boundary design note ADR-003 is indexed in `docs/adrs/README.md`).

## Not in this directory

- **Authentication / sessions** — owned by OCTO (`apps/octo/auth/`).
  Athena consumes sessions via the bridge.
- **Per-tenant data** — owned by OCTO. Athena reads through scoped
  endpoints; it never reaches into tenant DB files directly.
- **LLM inference** — owned by `apps/octo_llm/`. Athena triggers
  enrichment via the bridge's agent-query surface.

## Build + dev

The frontend dev server is `npm run dev` in `web/` (see `web/README.md`);
it proxies API calls to the backend that `scripts/start-dev-backend.sh`
starts. Full end-to-end dev launcher is `./scripts/dev.sh` (repo root).
