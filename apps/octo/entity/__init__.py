"""Entity resolution, slice 1 — "where and who, at time T, and how sure".

Design of record: `2026-10-01-entity-resolution-design.md` (B — lean,
query-time resolution over per-tenant time-interval lookups — with A's
invariants grafted on, the adversarial review G1-G11 folded in and Rick's
decisions of 2026-10-01: MAC auto-link with the MAC-anomaly safeguard, NO
masking of device names, response actions out of scope).

The package, per tenant, in `clients/<slug>/entities.db` (migration 040):

  db.py          the tenant's file: `TenantDB.for_tenant(slug)` refuses any
                 path outside `clients/<slug>/`; reads probe sqlite_master
                 and answer "unresolved", never a 500
  switch.py      the per-tenant rollout switch off | shadow | on (registry)
  tokens.py      per-tenant HKDF-keyed tokens (one key file, mode 600)
  normalize.py   IP / MAC / hostname / time normalisation (one place)
  sites.py       sites + vendor refs (operator wins on INSERT / UPDATE / DELETE)
  intervals.py   egress + lease intervals from snapshots and system-log edges
                 (honest slack, the gap rule, day-chunking, reconnect splits)
  feeders/       the UniFi feed consumer, the Datto inventory consumer, the
                 NextDNS device-presence consumer
  rules.py       the event rules (S1 S2 S-AGREE S-NARROW not_located
                 S-CONFLICT S3 D3 D4 D5 D7 N-DEV) and the scoring algebra
  linkrules.py   the link rules (L-UNIFI L-SOLE L-EGRESS N-SITE, the NextDNS
                 ↔ Datto device link) — only narrow evidence writes `auto`
  resolver.py    `Resolver.for_tenant(slug)`: one event → one stored answer
  explain.py     the "Why?" text, deterministic (never the LLM)
  ocsf.py        the answer as an OCSF enrichment — the event is never
                 rewritten
  checks.py      "NextDNS stopped reporting from a PC Datto says is online"
  worker.py      the one-minute sweep, revisits, bucket-close re-rank, the
                 nightly link rules
  retention.py   the entity retention classes (G11: candidate lists are cut
                 to a count when their leases go)

INVARIANTS (each has a test): one tenant per file, no table holds a slug; no
function takes two tenant slugs; tokens are keyed per tenant; event payloads
are never rewritten; an unmapped or ignored UniFi site writes nothing; two
consoles with the same site id stay separate (scopes are '<hostId>/<siteId>');
a name never decides; a fakeable key (MAC, UniFi client id, NextDNS device
name) never reaches "exact" — only an operator's confirmation does.
"""
