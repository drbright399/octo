# ADR-0003: A new bundle host becomes the OCTO host — fresh bundle build, the legacy host frozen as an archive

**Status:** accepted · 2026-09-12
**Decision maker:** Rick
**Builds on:** ADR-0002 (substrate pivot)

Hosts are named by role here: **the legacy host** ran OCTO as host services
until this decision; **the bundle host** runs the container bundle after it.

## Context

- **Capacity is decisive.** The legacy host is small and disk-bound: one
  spinning disk, the operational bottleneck an audit found (full-table queries
  time out during scans). The bundle host has an order of magnitude more cores
  and memory on an SSD array, and was close to idle once the substrate pivot
  removed its planned role as the AI-agent host. The whole data lake fits in
  its memory cache.
- **The new host lowers operational risk.** Maintenance on the legacy host had
  been disrupted by unreliable access before; access to the bundle host has
  been stable. Moving does not change the deployment's site-level risk, only
  which machine carries the load.
- **The bundle packaging already exists** (`apps/octo/Dockerfile` and a compose
  template: octo-core plus the egress-locked octo-llm sibling). Host services
  on the legacy host were always the interim; a container bundle was the
  original target.
- An audit of the legacy host found accumulated drift (parallel legacy
  services, unused units, ad-hoc configuration). A lift-and-shift would carry
  that drift across.

## Decision

1. **The bundle host is the OCTO production host**, running the container
   bundle.
2. **Fresh build, not migration.** The deployment is built clean from current
   `main`; components are ported only by explicit decision (a keep / toss
   review during build prep). Nothing is copied across wholesale.
3. **Clean-slate data.** The new bundle starts with a fresh registry and fresh
   per-tenant databases. Operators, clients, adapter instances and ingest
   tokens are re-provisioned (the onboarding wizard on `main` does this work).
4. **The legacy host becomes the legacy compliance archive.** At cutover its
   services stop, and the machine is kept, with no further writes, holding
   all pre-cutover tenant data (events, per-tenant audit chains, the global
   audit, the offboarded-tenant archive) for the retention window. Nothing
   historical is deleted by this decision.
5. **The legacy admin / ingest service is never ported.** The fresh build
   ships a bedrock-native ingest endpoint instead; buoys and the Wazuh shim get
   new tokens pointed at the bundle host at cutover.

## Keep / toss (build-prep review)

| Component | Verdict |
|---|---|
| bedrock API (`apps/octo` at `main`, incl. webhooks / tenant map / outbound mail) | **KEEP** — it is the build |
| Console v3 frontend (already on the bundle host) | KEEP — same host now, the proxy simplifies to a local upstream |
| Wazuh stack (already on the bundle host) + shim | KEEP — the shim target becomes local |
| Buoy fleet | KEEP — repoint + re-token at cutover |
| Threat-intel ingest jobs + intel DB | PORT deliberately (container or host scheduler; decided during prep) |
| Legacy admin / ingest service | **TOSS** — replaced by the bedrock ingest endpoint |
| Legacy relay / dashboard / per-client relay services | TOSS (already retired) |
| Legacy boot-notify / self-check scripts | TOSS — superseded by compose healthchecks + restart policies + (later) a morning watch |
| The legacy host's local LLM runtime | TOSS — the octo-llm sibling replaces it (CPU inference is viable on the bundle host; no GPU is assumed) |
| Pre-cutover tenant data + audit chains | ARCHIVE on the legacy host (compliance retention; per-tenant `retention_days`) |

## Required build items (gate cutover)

1. **Bedrock ingest endpoint** — HTTP ingest with client-token auth on
   octo-core (the one capability only the legacy service had).
2. Token minting for every buoy and the Wazuh shim against the new registry.
3. Bundle bring-up on the bundle host: SSD-backed state directory, compose from
   the template, bootstrap + migrations, operator provisioning.
4. Cutover runbook with rollback: the legacy host stays fully live until the
   bundle host has ingested and triaged real traffic; repoint one buoy first,
   watch, then the rest; freeze the legacy host only after N clean days.

## Consequences

- The two-host split (backend on the legacy host, frontend on the bundle host)
  ends; the console proxies to a local container. Several classes of past
  faults (cross-host relay, unreliable access mid-deploy) become structurally
  impossible.
- octo-llm becomes feasible (CPU inference on the bundle host), which unblocks
  the L2 triage escalation that had been dark.
- The earlier plan to deploy a pending range of `main` to the legacy host is
  **superseded**: current `main` deploys to the bundle host as the fresh build
  instead.
- Production client data now shares a machine with whatever else the bundle
  host runs, so host hygiene becomes a standing rule: the production host is a
  boring host (no experimental plugins or side projects on it).
- Compliance retention for pre-cutover data is satisfied by the legacy-host
  archive; the 90-day telemetry tier applies to the NEW lake from day one.
