# ADR-0002: OCTO is the data substrate; the orchestrator is the operator AI

**Status:** accepted · 2026-09-09
**Decision maker:** Rick
**Context window:** decided during the 2026-09-09 architecture review.

## Context

The original split (described in `docs/architecture.md`) planned two product
halves: OCTO as the multi-tenant data plane, and **Athena as an orchestrator built as
product code** — driving adapters through the intake → enrich → act → ticket →
learn loop with gated autonomy slices landing over time.

In practice, the operator-side assistant can run that loop on demand behind
human approval gates, reasoning per case — which covers what the planned
product slices would have done. Meanwhile OCTO does the half a chat session
cannot do: continuous ingest, tenant-isolated longitudinal storage with
hash-chained audit, and heuristic triage notes.

Building the orchestrator as product code would duplicate the weaker half of
an existing capability.

## Decision

1. **OCTO = the substrate.** Its job is to be the always-available,
   tenant-isolated history + sensor layer: ingest, store, triage-annotate,
   and serve per-client telemetry, alerts, notes, and patterns.
2. **The orchestrator = the operator AI, on demand.** The 1→N loop is not
   product code; the AI executes the workflow with operator approval gates.
3. **The integration seam is MCP + write-back.** The near-term build target:
   - an **OCTO-MCP server** exposing the existing bedrock API (auth, search,
     events, notes) to operator-AI sessions;
   - **note write-back**: findings from per-ticket work land in `agent_notes`
     / pattern links (loop step 10) so knowledge compounds in the substrate;
   - a **daily watch**: feed-health (last-event-age per source per tenant)
     + overnight anomaly digest delivered to the operator's morning sync.
4. **The console stays** as the human UI over the same API. Autonomy work is
   refocused on the one outcome-shaped slice a session can't do: continuous
   noise-dismissal round-trips at the source (north star, unchanged).

## Consequences

- The earlier ticket-action workflow design is superseded and retired.
- The earlier "sibling orchestrator" concept is retired.
- The legacy→bedrock consolidation gets a concrete driver: the substrate needs
  ONE ingest surface and ONE query surface.
- A legacy indicator-relay path is a candidate for retirement.
- Retention enforcement moves from "policy rows only" to an actual job the
  substrate runs.
