/**
 * Operator notices — mirrors `apps/octo/api/routers/admin_notices.py` (v0.10).
 *
 * When a super admin applies a tenant merge or offboard ALONE (the attested
 * single-person exception), every other admin+ gets one of these: shown on
 * every console load until they acknowledge it. The text is the server's
 * (who did what to which tenants, when) — never the typed attestation, which
 * lives on the change record in Settings → Tenants → Single-person changes.
 *
 * `mapping_review` (migration 038) is a PLATFORM notice (actor 0): tenant
 * mappings an earlier version made from a name match alone, listed once for
 * every admin to re-review under Settings → Integrations (the same-name
 * fix).
 *
 * `entity_review` (migration 040) is a PLATFORM notice too: entity
 * resolution hit a conflict for one client (a rule against an operator
 * decision, two sites claiming one alert, a NextDNS profile whose traffic
 * comes from none of the client's sites) — reviewed under Settings → Tenants
 * → Links to review, that client pre-selected. Its body lists the items one
 * per line.
 *
 * Tier Black (migration 044) adds the `threat_*` kinds: the in-app step of
 * the incident paging ladder (`threat_black`, `threat_red`,
 * `threat_escalation`), a client's lockdown / allow decision
 * (`threat_client`), a detection-coverage outage (`threat_coverage`) and a
 * registry change (`threat_registry`). Analysts are recipients of these.
 */

export type NoticeKind =
  | "single_attested_merge"
  | "single_attested_offboard"
  | "mapping_review"
  | "entity_review"
  | "threat_black"
  | "threat_red"
  | "threat_escalation"
  | "threat_client"
  | "threat_coverage"
  | "threat_registry";

export interface OperatorNotice {
  readonly id: number;
  readonly kind: NoticeKind | string;
  readonly actor_id: number;
  readonly subject_slug: string;
  readonly target_slug: string | null;
  readonly change_request_id: number | null;
  readonly title: string;
  readonly body: string;
  readonly created_at: string;
  readonly acknowledged_at: string | null;
  /** pending | sent | failed | not_configured | no_address — the e-mail copy. */
  readonly email_state: string;
}

export interface NoticeListResponse {
  readonly notices: readonly OperatorNotice[];
  /** Unacknowledged notices of the caller. */
  readonly open: number;
}
