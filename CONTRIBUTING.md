# Contributing to Athena / OCTO

Thanks for contributing. Two maintainers (see
[`MAINTAINERS.md`](MAINTAINERS.md) for who owns what) pair with Claude
agents (Code + Design). The bar: small clean PRs, tests at every
commit, no half-finished implementations, no commented-out code.
Security issues go through [`SECURITY.md`](SECURITY.md), not public issues.

If you're a Claude agent joining this repo, also read
[`docs/CLAUDE-ONBOARDING.md`](docs/CLAUDE-ONBOARDING.md).

## Workflow

1. Branch from `main` (`feat/<topic>` or `fix/<topic>`).
2. Make the smallest change that advances the topic.
3. Tests must pass at every commit (no "fix it in the next one").
4. Open a PR; describe the *why* in the body, not just the *what*.
5. Squash-merge unless the history is genuinely useful.

## Scope guardrails

- **Don't add features beyond what the task requires.** A bug fix
  doesn't need surrounding cleanup; a one-shot operation doesn't need
  a helper. Three similar lines is better than a premature
  abstraction.
- **Don't introduce dependencies casually.** New runtime deps need a
  one-line justification in the PR.
- **Don't break the bridge invariants.** The five invariants in
  `packages/shared-bridge/shared_bridge/invariants.py` are
  load-bearing for the security model. Changing one is an ADR-level
  decision.
- **Don't refactor the Protocol seams "to make them cleaner".** They
  are the swap points between in-memory test fakes and SQLite/HTTP
  prod. Drift between them turns into a compatibility nightmare.

## Code style

- **Python:** ruff + mypy strict. FastAPI + Pydantic v2.
- **TypeScript:** strict, including `noUncheckedIndexedAccess` and
  `exactOptionalPropertyTypes`. ESLint with zero warnings.
- **Tailwind:** semantic tokens (`bg-bg-card`, `text-accent`,
  `border-border-bright`) over arbitrary values. Tokens live in
  `apps/athena/web/tailwind.config.ts` + `src/index.css`.
- **Comments:** default to none. Only add when the *why* is
  non-obvious — a hidden constraint, a subtle invariant, a workaround
  for a specific bug. Don't restate what well-named code already says.

## Tests

- Backend: pytest. Each package has its own `tests/`. Aim for unit
  tests at the Protocol seam, not integration tests across the whole
  stack.
- Frontend: Vitest + Testing Library. Tests assert behavior + a11y, not
  implementation details (class names, internal state).
- Both: prefer `data-testid="…"` over selectors that depend on copy.

## Security

- **Never commit credentials.** `.gitignore` covers the obvious
  patterns; the pre-commit and pre-push hooks scan every commit with
  `scripts/scan_sensitive.py` (see [SECURITY.md](SECURITY.md)). Install
  them once per clone, and do not bypass them with `--no-verify`:
  ```bash
  scripts/install_hooks.sh
  ```
- **Never publish a copy by hand.** `scripts/publish_public.sh` is the only
  supported way to make a public copy.
- **Never put real customer data in mock files.** Synthetic only.
  `apps/athena/web/src/mock/` is the contained area.
- **Never store tokens in `localStorage` or `sessionStorage`.** Auth
  uses httpOnly cookies. UI preferences (theme) are fine in
  `localStorage`.
- **Server enforces, UI presents.** Don't move security checks into
  React components. Components must render correctly regardless of
  whether the data they receive should have been allowed in the
  first place.

## Code/Design collaboration pattern

This codebase mixes Claude Code (code-editing agents) and Claude
Design (visual + interaction-design agents). Two patterns work well:

- **Design-first:** for novel visuals, Design produces a static
  prototype + sample data shapes; Code integrates it into the
  framework. Sample-data shapes live at `docs/sample-data/`.
- **Code-first:** for forms and workflows where the constraint is the
  data contract, Code builds the wiring; Design polishes after.
- **Hybrid:** for things that already have a visual language (e.g.,
  variants of an existing widget), Code can land it directly using
  the established tokens; Design reviews.

Default is Design-first for new visual surfaces, Code-first for
forms/workflows.

## What goes in `docs/`

- Architectural specs and ADRs (decisions that shape the codebase).
- Sample-data input packages for Design-first work.
- Onboarding docs for new contributors and Claude agents.

What does **not** go in `docs/`:

- Operational runbooks tied to a specific live deployment.
- Sprint logs / decision logs / handoff notes that mention real
  customer or operator identities.
- Anything customer-bearing — those live in a parallel
  `docs/internal/` tree on each contributor's machine, gitignored.

## License

Athena / OCTO is licensed under the Apache License, Version 2.0
([`LICENSE`](LICENSE)). Unless you explicitly state otherwise, any
contribution you intentionally submit for inclusion is licensed under the
same terms, without any additional terms or conditions (section 5 of the
license). [`NOTICE`](NOTICE) carries the project's copyright and
attribution notice (Richard Benson and Zackary Hille); keep it with any
copy you redistribute (section 4). Third-party code comes in only under a
license compatible with Apache-2.0, with its own notice kept.

## Releases

There aren't any yet. When 1.0 lands, releases will be tagged
`v1.0.0` etc. and built from `main`.
