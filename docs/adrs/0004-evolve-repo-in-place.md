# ADR-0004: Evolve the existing `athena-octo` repo in place — no V2 repo

**Status:** accepted · 2026-09-16 (Rick delegated the call to Athena after reviewing the reasoning; revisit at the cutover build if new pain surfaces)
**Decision maker:** Rick
**Builds on:** ADR-0002 (substrate pivot), ADR-0003 (fresh bundle build on a new host)

## Context

The substrate pivot (ADR-0002) and the fresh bundle build (ADR-0003) reoriented
OCTO's *purpose* and its *runtime*. The open question this ADR settles: does the
**codebase** continue in this repo, or do we start a fresh "V2" repo?

Key facts:

- **"Fresh build" in ADR-0003 is about the runtime and the data, not the code.**
  The bundle host gets a clean bundle deploy with empty registry + per-tenant DBs. That
  delivers the entire clean-slate benefit at the *deployment* layer. The code layer
  and the data layer are independent; only the data/runtime needs to be reborn.
- **The bones are good — evidenced, not assumed.** The 2026-09-16 pre-work found
  that wiring the "first traffic" Datto RMM path was a *registration*, not a build:
  the webhook handler, the `DattoSourceAdapter`, the ingest sink, per-tenant DBs,
  the source-token auth, rate-limit middleware, and 8 vendor adapters on one
  consistent `BaseSourceAdapter` pattern already exist and are tested. The defects
  found were normal, contained bugs (a webhook-vs-API key-shape mismatch), fixed in
  a single adapter file with 14 new tests. That is a healthy codebase, not rot.
- **The repo carries the decision trail** — this ADR series, the roadmap, the
  session logs. For a security product, that audit lineage has real value and is
  painful to reconstruct.
- **We are mid-cutover.** The cutover build, the bedrock ingest gate, and the RMM
  first-traffic wiring all assume this repo. A V2 detour freezes them.
- The repo is already a **monorepo** (`apps/octo`, `apps/athena`, `apps/octo_llm`,
  `packages/*`), so a "clean core" can be a new app-module sharing the tested
  packages + history — no repo split required to get a fresh architectural surface.

## Decision

1. **Evolve `athena-octo` in place. Do not create a V2 repo.** The code continues on
   `main`; ADR-0003's "fresh build" is satisfied by fresh data + a clean bundle-host
   deploy, not by a new codebase.
2. **Reorient in place, not by starting over.** Where the abandoned separate-
   orchestrator direction (pre-ADR-0002) left dead code, *delete it in place*. If a
   fresh architectural surface is wanted for the substrate core, add it as a **new
   app-module** alongside the existing apps, reusing `packages/*` and the git history.
3. **Tag the cutover commit** so the frozen legacy archive (ADR-0003) is
   reproducible from history.
4. **Reserve a true V2 repo** only if a future finding shows the bones are actually
   wrong (tangled abstractions, wrong-framework debt). No such finding exists today.

## Consequences

- Keeps the tested base (auth, per-tenant DB, adapter framework, ingest,
  migrations, sanitized pool) and the full decision history. Avoids the second-system
  rewrite trap.
- The reorient work is *pruning + optional module carving*, which is cheaper and
  lower-risk than a rewrite and fits inside the cutover's "migration and reorient" work.
- If real architectural rot surfaces later, this ADR is superseded, not violated —
  the V2 option stays open, now with evidence behind it.

## Alternatives considered

- **Fresh V2 repo (rejected):** throws away tested infrastructure + the decision
  trail, invites the second-system rewrite trap, and stalls the in-flight cutover —
  with no rot to justify the cost.
- **Lift-and-shift of the legacy host to the bundle host as-is (already rejected in
  ADR-0003):** would migrate the legacy host's drift. ADR-0003's clean bundle build
  handles this at the runtime layer; ADR-0004 is the code-layer complement.
