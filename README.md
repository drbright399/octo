# Athena / OCTO

A multi-tenant security operations platform for managed service providers
(MSPs). Ingests telemetry from many vendor systems, normalizes it, and
surfaces findings + tickets through a single operator console.

> **Status: pre-1.0.** APIs and schemas may change between minor versions.
> Licensed under the [Apache License 2.0](LICENSE); copyright and
> attribution in [NOTICE](NOTICE).

---

## What this is

**Athena** is the orchestration layer — operator console, layout +
widget framework, ticket/finding workflows, the action-adapter surface
for outbound automation (device isolation, etc.).

**OCTO** is the data plane — the secured tenant-scoped data lake that
holds events, audit chains, registries, and the per-source query
templates Athena talks to.

The two halves communicate over a small, audited bridge with five
load-bearing invariants (closed template set, session-bound tenant,
hash-chained audit log, structured query results, single point of
control). See [`docs/architecture.md`](docs/architecture.md) for the
fuller picture.

```
     Athena Console (operators)            OCTO Core (data plane)
   ┌──────────────────────────┐         ┌─────────────────────────┐
   │  apps/athena/web         │         │  apps/octo              │
   │  ├─ widget framework     │         │  ├─ bridge server       │
   │  ├─ layout service       │  HTTPS  │  ├─ adapter registry    │
   │  └─ render components    │  bridge │  ├─ audit log (chained) │
   │     (apps/athena/widgets)│ ◄─────► │  └─ template executor   │
   └──────────────────────────┘         └─────────────────────────┘
                                              │
                                       ┌──────┴──────┐
                                       │  source     │
                                       │  adapters   │
                                       │  (RMM, EDR, │
                                       │   network,  │
                                       │   buoy, …)  │
                                       └─────────────┘
```

### Integrations

Source adapters live under `apps/octo/adapters/<vendor>/` and are
discovered at boot: Datto RMM, Wazuh, RocketCyber, UniFi, Autotask,
Resend (outbound mail) and **NextDNS** — per-site DNS security blocks and
protection health, polled per mapped profile with the cheap analytics
question first (the DNS log itself never comes into Athena). Each one's
behaviour, limits and wizard steps: [`apps/octo/README.md`](apps/octo/README.md).

## Who's working on this

Two maintainers (see [`MAINTAINERS.md`](MAINTAINERS.md)), both pairing
with Claude agents. Security reports go through
[`SECURITY.md`](SECURITY.md); contributions are welcome under the same
license (see [`CONTRIBUTING.md`](CONTRIBUTING.md)). **For Claude agents
joining this repo, start here:**
[`docs/CLAUDE-ONBOARDING.md`](docs/CLAUDE-ONBOARDING.md).

## Layout

```
athena-octo/
├── apps/
│   ├── athena/
│   │   ├── framework/        # Python: layout service, widget registry client, boot
│   │   ├── widgets/
│   │   │   └── components/   # TSX: render components (alert-feed, counter-grid, ...)
│   │   ├── adapters/         # Athena-side adapter integrations
│   │   └── web/              # Vite + React + TS frontend (the operator console)
│   └── octo/
│       ├── framework/        # Python: registries, bridge server, audit, templates
│       ├── adapters/         # OCTO-side source adapters (drop-in registration)
│       ├── main.py           # FastAPI entrypoint
│       └── Dockerfile        # Container build
└── packages/
    ├── shared-adapter-contract/   # Adapter Protocol + lifecycle types
    ├── shared-widget-contract/    # Widget Protocol + layout types
    └── shared-bridge/             # Bridge Protocol, invariants, audit shapes
```

## Quickstart

### Backend (Python)

```bash
# One-time: create a venv at packages/.venv, install all in-tree
# packages + per-app deps editable.
python3 -m venv packages/.venv
source packages/.venv/bin/activate
pip install -e packages/shared-adapter-contract \
            -e packages/shared-widget-contract \
            -e packages/shared-bridge \
            -r apps/octo/requirements.txt

# Run all tests (Phase 2 backend — 266 tests, ~3s).
for d in packages/shared-adapter-contract packages/shared-widget-contract \
         packages/shared-bridge apps/octo/framework apps/athena/framework apps/octo; do
  echo "--- $d ---"
  (cd "$d" && python -m pytest tests/ -q | tail -3)
done

# Spin OCTO up locally (no Docker). Generate your own bootstrap token,
# never reuse an example value. Each token must be at least 32 random
# characters with no whitespace, or OCTO refuses to start:
#   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
OCTO_REGISTRY_DB_PATH=/tmp/octo-reg.db \
OCTO_AUDIT_DB_PATH=/tmp/octo-audit.db \
OCTO_BOOTSTRAP_TOKENS="<random-32+-char-token>=1:super_admin:msp_root:s1" \
uvicorn apps.octo.main:app --port 8001
```

`OCTO_BOOTSTRAP_TOKENS` (format `token=operator_id:role:tenant:session_id`,
comma-separated) is a dev-only static bearer map read by the bridge-only
app `apps.octo.main`. Leave it unset in any real deployment. A weak or
repeated token, or a malformed entry (no `=`, not exactly four session
fields, an operator_id that is not a positive number, an unknown role,
an empty tenant or session_id), stops the app at startup; the error names
the entry's position, never the token.

### OCTO container (Docker)

```bash
docker build -f apps/octo/Dockerfile -t athena/octo-core:v0.1 .
# The default command serves the full API (apps.octo.api), which ignores
# OCTO_BOOTSTRAP_TOKENS; override it to run the bridge-only app:
docker run --rm -p 8001:8001 \
  -v /opt/octo-state:/var/lib/octo/state \
  -e OCTO_BOOTSTRAP_TOKENS="<random-32+-char-token>=1:super_admin:msp_root:s1" \
  athena/octo-core:v0.1 \
  uvicorn apps.octo.main:app --host 0.0.0.0 --port 8001
```

### Frontend (Vite + React)

```bash
cd apps/athena/web
npm install
npm run dev          # http://localhost:5173
npm run typecheck
npm run lint
npm test             # Vitest + Testing Library
npm run build
```

The dev server uses synthetic mock data (no backend required). Real
bridge wiring lands as a follow-up sprint.

## What's mock and what's real

This is critical for anyone making changes:

- **`apps/athena/web/src/mock/`** — synthetic data only, used by the
  dev server. Replaced at runtime once the bridge client is wired
  through. Never put real customer data here.
- **`apps/athena/web/src/lib/api.ts`** — has a `USE_MOCK = true` flag
  at the top. While true, the API client returns mock data; flip it
  off when running against a live OCTO.
- **Backend (Python)** — runs against a real SQLite by default; tests
  use `:memory:` or `tmp_path`. No mock layer — the Protocol seams
  swap real for in-memory implementations directly.

## Security baseline

- **No credentials in the repo.** `.gitignore` covers `.env`, `*.pem`,
  `*.key`, `*.gpg`, `secrets/`, `credentials/`.
- **No tokens in `localStorage`.** Auth uses httpOnly cookies set by
  the auth-core. Theme preference is the only thing browser-persisted.
- **All UI content rendered as text nodes.** No `innerHTML`, no
  `dangerouslySetInnerHTML`. Tested.
- **Adapter credentials enter via the UI form, encrypted server-side
  before persistence.** The browser sends the value once over HTTPS
  and never sees it again.
- **Secret guardrails: install the hooks once per clone. Every
  collaborator and every agent:** `scripts/install_hooks.sh`. The
  pre-commit hook scans what a commit adds, the commit-msg hook its
  message, and the pre-push hook every commit a push sends and the
  branch / tag name it creates on the remote, all with
  `scripts/scan_sensitive.py`
  (secrets, never-commit files, and your gitignored
  `.githooks/.local-block` terms). A public copy is made ONLY with
  `scripts/publish_public.sh`. Details and how to report an exposure:
  [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for PR workflow, scope
guardrails, and how Code/Design Claude agents collaborate on this
codebase.

## License

Copyright 2026 Richard Benson and Zackary Hille. Licensed under the
Apache License, Version 2.0: see [LICENSE](LICENSE) for the terms and
[NOTICE](NOTICE) for the attribution notice that travels with every copy.
Distributed on an "AS IS" basis, without warranties or conditions of any
kind.
