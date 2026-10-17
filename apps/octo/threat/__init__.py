"""Tier Black, slice 1 — incident records, the threat layer, paging, the
client view and the rule plumbing (design 2026-10-02, section 7.1, plus
Rick's section-9 decisions).

  store.py      the per-tenant incident records (events.db, migration 044)
  windows.py    evidence windows (Rick, 2026-10-05): a confirmed threat's
                first detection → its all-clear is evidence, kept by every
                retention path until an admin releases it
                (`apps.octo.retention.evidence` is what the prunes ask)
  registry.py   the registry facts the rules read: asset tags (life_safety
                first), verdicts, exceptions, the canary scanner allowlist,
                tier settings, the worker's state
  rules.py      the frozen rule registry (stage constants; no settings key)
  evaluators.py R6 (deception) and R2-W (Wazuh malware) — slice 1's
                automated rules, both SHADOW
  intake.py     FR2: detection blindness, measured by intake health
  coverage.py   per-tenant, per-rule "inputs configured and fresh" (P8)
  notify.py     notify_threat(): the paging ladder (analysts in scope too)
  client_view.py the neutral client line and the client's two actions
  lockdown.py   lockdown requests — 911 / life-safety assets are ALWAYS
                carved out (by canonical identity, never by spelling)
  identity.py   canonical asset identity: a short host name, an address /
                network — or none (never assumed "not a match")
  restricted.py RESTRICTED evidence (v0.17.1, rule B7 — CSAM lookups): kept
                apart from every event, admin-only, never enriched or
                previewed (`refuse_enrichment` is the gate), the fixed
                checklist and the "DO NOT OPEN" warning
  brake.py      the storm brake (one automated rule at a Red ceiling, ≤ 24 h)
  engine.py     TierWorker — opens, appends, raises; NEVER closes or lowers
  audit.py      the audit helper (system actor `system:tier-engine`)

Nothing here executes a network change, a block, an isolation or an
unblock: slice 1 RECORDS decisions and proposes; the response slice acts.
"""
