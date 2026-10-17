# Claude onboarding — Athena/OCTO

You're a Claude agent (Code or Design) joining a small private
collaboration. Two human contributors are already here. This document is
your starting point.

> **Read [`docs/NON-NEGOTIABLES.md`](NON-NEGOTIABLES.md) before you write
> a single line.** Those rules are not preferences. They constrain every
> task you take on in this repo.

## What you're working on

A multi-tenant security operations platform for managed service
providers. Athena = operator-facing control plane. OCTO = secured
tenant-scoped data lake. They communicate over an audited bridge with
five hard invariants.

Read [`docs/architecture.md`](architecture.md) first. Then come back.

## What you can confidently change

| Area | Code change without ADR? |
|---|---|
| `apps/athena/web/src/components/`, `pages/`, `lib/` | ✅ yes |
| `apps/athena/widgets/components/*.tsx` (render components) | ✅ yes — they're typed and isolated |
| `apps/athena/web/src/mock/*` | ✅ yes — synthetic data |
| `apps/athena/web/tests/` | ✅ yes |
| `apps/athena/web/tailwind.config.ts` + `index.css` (theme tokens) | ⚠ small additions ok; large reshapes coordinate first |
| `apps/octo/adapters/<slug>/` | ✅ yes for new adapter classes |
| `apps/octo/framework/` (registries, bridge server, audit) | ⚠ Protocol seams are load-bearing — coordinate |
| `packages/shared-*/` (contracts) | 🛑 ADR-level. Both halves depend on these |
| `packages/shared-bridge/shared_bridge/invariants.py` | 🛑 ADR-level. Security-critical |

## Stack you're working in

**Frontend (apps/athena/web):**
- Vite 6 · React 19 · TypeScript strict (`noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`)
- Tailwind 3 with **semantic tokens** — `bg-bg-card`, `text-accent`,
  `border-border-bright`. Token values are CSS variables defined in
  `src/index.css` for dark + light themes.
- Vitest + Testing Library. Tests assert behavior + a11y, not class
  names.
- Hash-based router in `src/lib/router.ts`. No react-router.

**Backend (apps/octo, apps/athena/framework, packages):**
- Python 3.12 · FastAPI · Pydantic v2 · ruff + mypy strict
- Per-package `tests/` directory; run with `pytest -q`
- Protocol-based seams (in-memory + SQLite + HTTP impls of the same
  Protocol). Don't refactor away from Protocols — they're the swap
  points.

## Conventions

- **Comments default to none.** Add one only when the *why* is
  non-obvious.
- **Don't add features beyond the task.** Bug fix → bug fix. No
  surrounding cleanup unless requested.
- **Don't introduce dependencies casually.** New deps need a one-line
  justification.
- **Tests must pass at every commit.** No "fix it in the next one."
- **Components render text as text nodes.** Never `innerHTML` /
  `dangerouslySetInnerHTML`. Tested with XSS payloads in
  `tests/default-alert-feed.test.tsx`.
- **Tokens never go in `localStorage`.** Auth = httpOnly cookies. UI
  preferences (theme) are fine in `localStorage`.

## How to run things

```bash
# Frontend (most common — visual work)
cd apps/athena/web
npm install
npm run dev          # http://localhost:5173 (synthetic mock data, no backend)
npm run typecheck    # tsc -b --noEmit
npm test             # Vitest
npm run build        # production build

# Backend (less common during UI work)
python3 -m venv packages/.venv
source packages/.venv/bin/activate
pip install -e packages/shared-adapter-contract \
            -e packages/shared-widget-contract \
            -e packages/shared-bridge \
            -r apps/octo/requirements.txt
# All tests, all packages:
for d in packages/shared-* apps/octo/framework apps/athena/framework apps/octo; do
  echo "--- $d ---"
  (cd "$d" && python -m pytest tests/ -q | tail -3)
done
```

## Code/Design collaboration patterns

Two patterns work well; the right one depends on what you're building:

### Design-first (preferred for novel visual surfaces)

A Design Claude produces:

1. A static prototype (HTML/CSS or Figma export of the visual)
2. A `docs/sample-data/<topic>.json` file with sample rows in the
   typed shape the component expects

A Code Claude then:

1. Imports the sample data into a Vitest snapshot fixture
2. Writes the typed render component against the sample data
3. Wires it into the dashboard or settings page

`docs/sample-data/` exists for exactly this handoff. Sample shapes are
synthetic and committed.

### Code-first (preferred for forms, workflows, contract-driven UI)

A Code Claude lands the form/workflow plumbing using the existing
visual tokens, then a Design Claude polishes spacing, copy,
microinteractions in a follow-up PR.

This is how `apps/athena/web/src/pages/settings/integrations.tsx` was
built — the form wiring + drawer interaction came first, polish later.

### Hybrid

For variants of an existing visual language (e.g., a new variant of
the alert-feed for a different severity scheme), Code can land it
directly using established tokens; Design reviews and tunes after.

## What goes in commits

- **PR title:** under 70 characters. Lead with the *what*, not the
  *why*.
- **PR body:** the *why*. What problem this solves, what alternatives
  were considered, what the change does NOT do.
- **Commit messages:** present tense, imperative ("add X", "fix Y",
  not "added", "fixes").
- **Tests:** changes should add or update tests. Pure-refactor PRs
  that only move code without behavior change can skip new tests but
  must keep existing ones green.

## What never goes in commits

- Real customer names, tenant slugs, operator identities. The
  pre-commit and pre-push hooks block known patterns; if yours isn't
  covered, add it to `.githooks/.local-block` (gitignored) on your
  machine. **Run `scripts/install_hooks.sh` once in every clone you work
  in**, and never commit or push with `--no-verify`. Public copies are
  made only with `scripts/publish_public.sh` (see `SECURITY.md`).
- Private-infrastructure detail: host nicknames, hardware models, live
  fleet counts, tailnet tags or addresses, ports and paths tied to our
  hosts. Name hosts by role ("the bundle host", "the legacy host", "the
  backup vault", "the operator workstation", "the reverse proxy"); see
  the 2026-10-16 rule in [`docs/NON-NEGOTIABLES.md`](NON-NEGOTIABLES.md).
  Rick, Zack and Micro-IT may be named; clients never.
- Credentials of any kind — even sample/test ones. Use `.env.example`
  or `secrets-template.json` patterns instead, with placeholder
  values like `sk-REPLACE_ME`.
- `.env` files, `.gpg` files, `*.key` / `*.pem` — `.gitignore` covers
  these.
- TODO / FIXME comments without an attached issue link or owner.
  Either fix it in the PR or capture it as an issue.

## Where to ask questions

There's no Slack channel. Open a PR with a draft + question in the
description, or leave a comment on an existing PR. The other
contributors will respond when they're online.

## Read these next

- [`docs/NON-NEGOTIABLES.md`](NON-NEGOTIABLES.md) — **rules you cannot break**
- [`docs/architecture.md`](architecture.md) — full architecture overview
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — PR workflow + scope guardrails
- `apps/athena/web/README.md` — frontend-specific layout conventions
- A few existing render components to copy the pattern:
  - `apps/athena/widgets/components/default-alert-feed.tsx` (list-shaped)
  - `apps/athena/widgets/components/default-counter-grid.tsx` (KPI tile)
  - `apps/athena/widgets/components/default-attention-rotator.tsx` (carousel with priority sort)
