# Audit policy

What OCTO writes to its audit chain, and when. Code comments cite this page
as `docs/audit-policy.md`.

One chain: `global/audit.db::audit_log` (`apps/octo/auth/audit.py`),
append-only (UPDATE / DELETE triggers), hash-chained, `audit.verify` walks
it. Nothing below rewrites history; it only decides what gets appended. Why:
dashboard polling had buried every decision under list reads.

| Class | Chain rows | Routes → actions |
|---|---|---|
| Writes / state changes | one per call, written before (or with) the change | every mutating route: `tickets.create/patch/bulk_patch/note.create/charge.*/push.enqueue`, `tenant_*` (incl. `tenant_location_set` / `tenant_location_clear`), `quarantine_route/discard`, `adapter_*` (incl. `adapter_smoke_test`), `admin_ops_*`, `l2_llm_*`, `octo_llm_*`, `admin_data.retention_update`, `retention_enforce` (system `retention-job`, one per tenant WITH deletions per enforcing run, before them) + `retention_run` (one per enforcing run, after it), `buoy.command_queued`, `buoy_*_note_*`, `integrations.autotask.*`, `operator_preferences_update`, bootstrap / recovery |
| Auth + step-up | one per event | `auth_*`, `step_up_granted`, `step_up_failed` |
| On-demand sensitive reads | one per call | step-up search: `search.events`, `search.event_payload`, `search.indicators`, `search.links_expand`, `search.export`, `search.dns_summary` (unmasked DNS telemetry), `search.nextdns` (live NextDNS logs, masked, not stored); one ticket's full detail: `tickets.fetch`; a raw held payload: `quarantine_fetch`; raw reject excerpts: `sanitization.rejects_fetch` (super_admin); stored vendor credentials used: `adapter_vendor_tenant_list` (vendor contact only, cache hits not); agent queries: `octo_llm_query_*` |
| Polled reads | hourly roll-up per (operator, session, action) | `tickets.list`, `agent.activity.fetch`, `admin_data.storage_stats_fetch` + `admin_data.retention_fetch`, `fleet.sites` + `fleet.site_alerts` |
| Not audited | none | scope-gated metadata / aggregates / status, many polled: `dashboard/*` (masked values only), buoy fleet + command history + notes lists, whoami / me / sessions / preferences / llm-status, agent status, step-up status, admin list views, ticket notes / charges / push-state (covered by that ticket's `tickets.fetch` row), sanitization reject counts, tiles |

## Roll-up

`apps/octo/auth/audit_rollup.py`, one `PolledReadAudit` per app on
`app.state`: the FIRST call of an (operator, session, action, UTC hour)
window appends an `open` row synchronously (same action name,
`after_state.rollup = "open"`, window start / end, session prefix, the first
call's detail), so the access is on disk the moment it happens. Later calls
in the hour only count in memory. Once the hour is over, the next polled
read from ANY caller appends the window's `close` row (`rollup = "close"`:
calls, first / last call time, rows_returned, distinct request `shapes`
capped at 20, free text only ever as `*`, plus `open_row_id` /
`open_request_id`). App shutdown flushes every open window as a `close` with
`partial: true`. An `open` without a `close` = the process died in that hour
(count lost, access not). Failure to write an open row fails the read, as
every audit write does.

## Rule for new routes

- Mutates → one row per call.
- Hands out raw tenant data, secrets or exports on demand → one row per call.
- Polled by the UI on a timer → `PolledReadAudit.for_app(request.app).record(...)`.
- Scope-gated metadata / aggregates → not audited.

Tenant lifecycle history is the global chain (`tenant_*` rows,
`target_kind = 'client'`, `client_slug` = the tenant).
