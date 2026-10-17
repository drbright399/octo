"""Human verdicts on ALERTS (v0.17.2, Rick's decisions A and B, 2026-10-06).

  ACKNOWLEDGE  (analyst+, per alert, an optional note ≤ 500, audited before
               the write) — the alert leaves the "needs attention" list and
               stops contributing to its site's Yellow; a NEW occurrence (a
               new alert, or a coalesced row's count / last-seen growing past
               the ack) re-surfaces it. Optional "acknowledge repeats for 24
               h" for the same (tenant, device, signature key), expiring by
               itself.
  EXPECTED     (analyst+, a reason ≥ 10 characters, a review date ≤ 90 days)
               — an expected condition (tenant + device + signature key, +
               optionally a remote for a network alert) labels matching
               alerts "expected (rule #N)": grey, not Yellow, still stored.
               Revocable (audited); the admins are reminded 7 days before the
               review date; on it the rule stops matching (no renewal).
               NEVER for a NextDNS 'csam' block, an alert an incident rests
               on, a decoy alert or anything that would open a Red / Black.
  VERDICTS     every human verdict (ack / confirmed (R8) / expected) is a row
               of `alert_verdict` (event id, tenant, signature key, verdict,
               actor, at, note) — training labels for later.
  RECALL       (v0.17.5, analyst+, a reason ≥ 10, audited before the write)
               an acknowledgement no longer covers anything — its alert, the
               other rows of its vendor alert and its repeats need attention
               again and count towards the site's colour; final (acknowledge
               again = a new ack). NOTES: additive context under an ack (≤
               500, newest last). Both are append-only rows of
               `alert_verdict_followup` (048); the ack row is never touched.

An event is NEVER deleted or altered by any of it (it stays for correlation,
the cross-tenant pattern pool and evidence windows), and Red / Black — the
incidents — are never touched: only the health layers' Yellow reads these.

  keys          device / signature keys, expected eligibility
  store         the registry rows (writes take the caller's transaction)
  state         the evaluator: open / acknowledged / expected / resurfaced
  occurrences   alerts as occurrences (ledger buckets, event rows)
  reminders     the review reminder (the tier worker's pass)
"""
