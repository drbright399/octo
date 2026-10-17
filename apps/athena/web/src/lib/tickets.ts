/**
 * Tickets API client.
 *
 * Talks to the /api/v1/tickets surface added in OCTO migration 013. All
 * calls are session-authed (no step-up — tickets are operator daily-work,
 * not the cross-tenant TI pool).
 */
import { ApiError } from "@/lib/api";

export interface TicketSummary {
  id: number;
  client_slug: string;
  autotask_id: string | null;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: TicketStatus;
  assignee_operator_id: number | null;
  queue: string | null;
  source_event_id: number | null;
  opened_at: string;
  updated_at: string;
  agent_note_count: number;
}

export type TicketStatus =
  | "new"
  | "in_progress"
  | "waiting_customer"
  | "waiting_vendor"
  | "resolved"
  | "closed"
  | "reopened";

export interface TicketStatusEvent {
  from_status: string | null;
  to_status: string;
  changed_by_operator_id: number | null;
  reason: string;
  source: "operator" | "autotask_sync" | "agent_action" | "system";
  changed_at: string;
}

export interface AgentInsight {
  agent_id: "octo" | "athena";
  note_text: string;
  confidence: number;
  created_at: string;
}

export interface AgentPatternEdge {
  from_kind: "ticket" | "event";
  from_id: number;
  to_kind: "event" | "ticket" | "indicator";
  to_id: number;
  relation: string;
  strength: number;
  rationale: string;
  created_by_agent: "octo" | "athena";
  created_at: string;
}

export interface TicketChargeRow {
  id: number;
  name: string;
  description: string;
  unit_cost: number;
  unit_price: number;
  quantity: number;
  is_billable: boolean;
  billing_code_id: string | null;
  autotask_charge_id: string | null;
  created_by_operator_id: number | null;
  created_at: string;
  last_pushed_at: string | null;
}

export type AutotaskPushStateValue =
  | "pending" | "in_flight" | "pushed" | "failed";

export interface TicketPushStateRow {
  state: AutotaskPushStateValue;
  attempts: number;
  last_attempt_at: string | null;
  last_error: string | null;
  autotask_ticket_id: string | null;
  queued_at: string | null;
  queued_by_operator_id: number | null;
}

export interface TicketDetail extends TicketSummary {
  description: string;
  closed_at: string | null;
  last_autotask_sync_at: string | null;
  due_at: string | null;
  push_to_autotask: boolean;
  is_billable: boolean;
  billing_code_id: string | null;
  contract_id: string | null;
  charges: TicketChargeRow[];
  push_state: TicketPushStateRow | null;
  status_history: TicketStatusEvent[];
  agent_insights: AgentInsight[];
  agent_pattern_links: AgentPatternEdge[];
}

export interface TicketListResponse {
  tickets: TicketSummary[];
  total: number;
  page_size: number;
  offset: number;
  tenants_searched: string[];
}

export interface TicketListParams {
  tenant?: string;
  status?: "open" | "closed" | "all";
  assignee?: "me" | number;
  /** Comma-separated severities to filter to. */
  severity?: string;
  /** Exact-match queue label. */
  queue?: string;
  /** Free-text — LIKE %q% over title + description. */
  q?: string;
  pageSize?: number;
  offset?: number;
}

export async function listTickets(
  params: TicketListParams = {},
): Promise<TicketListResponse> {
  const q = new URLSearchParams();
  if (params.tenant) q.set("tenant", params.tenant);
  if (params.status) q.set("status", params.status);
  if (params.assignee !== undefined) {
    q.set("assignee", params.assignee === "me" ? "me" : String(params.assignee));
  }
  if (params.severity) q.set("severity", params.severity);
  if (params.queue) q.set("queue", params.queue);
  if (params.q) q.set("q", params.q);
  if (params.pageSize !== undefined) q.set("page_size", String(params.pageSize));
  if (params.offset !== undefined) q.set("offset", String(params.offset));
  const qs = q.toString();
  const res = await fetch(`/api/v1/tickets${qs ? `?${qs}` : ""}`, {
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Failed to list tickets",
      res.status,
    );
  }
  return (await res.json()) as TicketListResponse;
}

export async function getTicket(slug: string, id: number): Promise<TicketDetail> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${id}`,
    { credentials: "include" },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Failed to load ticket",
      res.status,
    );
  }
  return (await res.json()) as TicketDetail;
}

export interface TicketPatchBody {
  status?: TicketStatus;
  severity?: "info" | "low" | "medium" | "high" | "critical";
  assignee_operator_id?: number | null;
  due_at?: string | null;
  reason?: string;
}

// Autotask-aligned per-ticket notes (migration 014).
export interface TicketNote {
  id: number;
  ticket_id: number;
  autotask_id: string | null;
  title: string | null;
  body: string;
  note_type: TicketNoteType;
  publish: TicketNotePublish;
  author_operator_id: number | null;
  created_at: string;
  updated_at: string;
  last_activity_at: string;
  pushed_to_autotask_at: string | null;
}

export type TicketNoteType =
  | "task_detail"
  | "workflow"
  | "internal"
  | "detail"
  | "summary"
  | "resolution"
  | "system_workflow";

export type TicketNotePublish =
  | "internal"
  | "all_autotask_users"
  | "client_portal";

export interface TicketNoteCreateBody {
  title?: string | undefined;
  body: string;
  note_type?: TicketNoteType | undefined;
  publish?: TicketNotePublish | undefined;
}

export async function listTicketNotes(
  slug: string, ticketId: number,
): Promise<TicketNote[]> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${ticketId}/notes`,
    { credentials: "include" },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Failed to load notes",
      res.status,
    );
  }
  return ((await res.json()) as { notes: TicketNote[] }).notes;
}

export async function createTicketNote(
  slug: string, ticketId: number, body: TicketNoteCreateBody,
): Promise<TicketNote> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${ticketId}/notes`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  if (!res.ok) {
    const body2 = await res.json().catch(() => ({}));
    throw new ApiError(
      (body2 as { code?: string; message?: string }).code
        || (body2 as { message?: string }).message
        || "Failed to create note",
      res.status,
    );
  }
  return (await res.json()) as TicketNote;
}

// Agent activity feed — surfaces recent agent_notes across the
// caller's tenants. UI on /tickets renders it as a "what is octo
// working on" strip. Groundwork for future auto-triage status.
export interface AgentActivityItem {
  client_slug: string;
  agent_id: "octo" | "athena";
  ref_kind: "event" | "ticket" | "indicator";
  ref_id: number;
  note_text: string;
  confidence: number;
  created_at: string;
  /** Slice 7d: which canned-query template produced this note.
   *   NULL or 'auto_enrich' — autonomous (octo wrote on its own)
   *   tell_me_more / recognized_patterns / compare_recent /
   *   suggest_disposition / suggest_next_steps — operator asked
   * Surfaces in the triage feed as a small chip so the operator can
   * distinguish "octo volunteered" from "I asked octo about this." */
  query_kind: string | null;
  /** When ref_kind='event' and a ticket was derived from that event,
   * the derived ticket's id + title. NULL for orphan events. */
  linked_ticket_id: number | null;
  linked_ticket_title: string | null;
  /** When ref_kind='ticket', the ticket's source_event_id (if any). */
  linked_event_id: number | null;
}

/** The operator-triggered "ask octo" kinds — the closed set mirrored from
 *  octo-llm's QueryKind (`AskOctoQueryKind` in lib/api). */
const ASK_QUERY_KINDS: ReadonlySet<string> = new Set([
  "tell_me_more", "recognized_patterns", "compare_recent",
  "suggest_disposition", "suggest_next_steps",
]);

export interface AgentNoteKindChip {
  readonly label: string;
  readonly title: string;
  readonly tone: "ask" | "vendor";
}

/** The feed chip for a note's `query_kind`: "ask:<kind>" ONLY for the closed
 *  set of operator questions; "vendor update" for a note Athena recorded
 *  from a vendor (e.g. a PSA ticket RocketCyber attached later — never an
 *  operator's ask); none for autonomous notes (NULL / auto_enrich) or an
 *  unknown kind (never claim an operator asked). */
export function agentNoteKindChip(kind: string | null | undefined): AgentNoteKindChip | null {
  if (!kind) return null;
  if (ASK_QUERY_KINDS.has(kind)) {
    return { label: `ask:${kind.replace(/_/g, "-")}`,
             title: `Operator asked: ${kind.replace(/_/g, " ")}`, tone: "ask" };
  }
  if (kind === "vendor_update") {
    return { label: "vendor update",
             title: "Recorded from a vendor update (not an operator question)", tone: "vendor" };
  }
  return null;
}

export interface AgentActivityResponse {
  items: AgentActivityItem[];
  tenants_searched: string[];
  limit: number;
}

export async function fetchAgentActivity(
  opts: { limit?: number; refKind?: "event" | "ticket" | "indicator" } = {},
): Promise<AgentActivityResponse> {
  const q = new URLSearchParams();
  if (opts.limit !== undefined) q.set("limit", String(opts.limit));
  if (opts.refKind) q.set("ref_kind", opts.refKind);
  const qs = q.toString();
  const res = await fetch(`/api/v1/agent/activity${qs ? `?${qs}` : ""}`, {
    credentials: "include",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || "Failed to load agent activity",
      res.status,
    );
  }
  return (await res.json()) as AgentActivityResponse;
}

export interface TicketChargeInput {
  name: string;
  description?: string | undefined;
  unit_cost?: number | undefined;
  unit_price?: number | undefined;
  quantity?: number | undefined;
  is_billable?: boolean | undefined;
  billing_code_id?: string | null | undefined;
}

export interface TicketCreateBody {
  title: string;
  description?: string | undefined;
  severity?: "info" | "low" | "medium" | "high" | "critical" | undefined;
  status?: TicketStatus | undefined;
  assignee_operator_id?: number | undefined;
  queue?: string | undefined;
  source_event_id?: number | undefined;
  push_to_autotask?: boolean | undefined;
  is_billable?: boolean | undefined;
  billing_code_id?: string | null | undefined;
  contract_id?: string | null | undefined;
  charges?: TicketChargeInput[] | undefined;
}

export async function createTicket(
  slug: string, body: TicketCreateBody,
): Promise<TicketDetail> {
  const res = await fetch(`/api/v1/tickets/${encodeURIComponent(slug)}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const body2 = await res.json().catch(() => ({}));
    throw new ApiError(
      (body2 as { code?: string; message?: string }).code
        || (body2 as { message?: string }).message
        || "Failed to create ticket",
      res.status,
    );
  }
  return (await res.json()) as TicketDetail;
}

export async function patchTicket(
  slug: string,
  id: number,
  body: TicketPatchBody,
): Promise<TicketDetail> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${id}`,
    {
      method: "PATCH",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  if (!res.ok) {
    const body2 = await res.json().catch(() => ({}));
    throw new ApiError(
      (body2 as { code?: string; message?: string }).code
        || (body2 as { message?: string }).message
        || "Failed to update ticket",
      res.status,
    );
  }
  return (await res.json()) as TicketDetail;
}

// ---------------------------------------------------------------------------
// P4-c2: charges + Autotask push helpers
// ---------------------------------------------------------------------------

export async function listTicketCharges(
  slug: string, ticketId: number,
): Promise<TicketChargeRow[]> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${ticketId}/charges`,
    { credentials: "include" },
  );
  if (!res.ok) {
    throw new ApiError("Failed to load charges", res.status);
  }
  return (await res.json()) as TicketChargeRow[];
}

export async function addTicketCharge(
  slug: string, ticketId: number,
  body: TicketChargeInput,
): Promise<TicketChargeRow> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${ticketId}/charges`,
    {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { code?: string; message?: string }).code
        || (b as { message?: string }).message
        || "Failed to add charge",
      res.status,
    );
  }
  return (await res.json()) as TicketChargeRow;
}

export async function deleteTicketCharge(
  slug: string, ticketId: number, chargeId: number,
): Promise<void> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${ticketId}/charges/${chargeId}`,
    { method: "DELETE", credentials: "include" },
  );
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { code?: string; message?: string }).code
        || (b as { message?: string }).message
        || "Failed to delete charge",
      res.status,
    );
  }
}

/** GET /tickets/_meta — what the console may offer on the tickets surface.
 *  `psa_writes_enabled` is the PSA (Autotask) writes kill switch: while it
 *  is false every "push to Autotask" option is hidden, and the server
 *  answers both enqueue paths with 409 PSA_WRITES_DISABLED. */
export interface TicketsMeta {
  psa_writes_enabled: boolean;
}

export async function fetchTicketsMeta(): Promise<TicketsMeta> {
  const res = await fetch("/api/v1/tickets/_meta", { credentials: "include" });
  if (!res.ok) {
    throw new ApiError("Failed to load ticket settings", res.status);
  }
  const body = (await res.json()) as Partial<TicketsMeta>;
  // Fail closed: anything but an explicit `true` means writes are off.
  return { psa_writes_enabled: body.psa_writes_enabled === true };
}

export async function requestAutotaskPush(
  slug: string, ticketId: number,
): Promise<TicketPushStateRow> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${ticketId}/push-to-autotask`,
    { method: "POST", credentials: "include" },
  );
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { code?: string; message?: string }).code
        || (b as { message?: string }).message
        || "Failed to enqueue push",
      res.status,
    );
  }
  return (await res.json()) as TicketPushStateRow;
}

export async function fetchPushState(
  slug: string, ticketId: number,
): Promise<TicketPushStateRow | null> {
  const res = await fetch(
    `/api/v1/tickets/${encodeURIComponent(slug)}/${ticketId}/push-state`,
    { credentials: "include" },
  );
  if (!res.ok) {
    throw new ApiError("Failed to load push state", res.status);
  }
  return (await res.json()) as TicketPushStateRow | null;
}

// ---------------------------------------------------------------------------
// P5-c: bulk-patch
// ---------------------------------------------------------------------------

export interface TicketBulkRef {
  slug: string;
  ticket_id: number;
}

export interface TicketBulkPatchOutcome {
  slug: string;
  ticket_id: number;
  ok: boolean;
  error_code: string | null;
  error_message: string | null;
}

export interface TicketBulkPatchResponse {
  results: TicketBulkPatchOutcome[];
  succeeded: number;
  failed: number;
}

export async function bulkPatchTickets(
  refs: TicketBulkRef[],
  patch: TicketPatchBody,
): Promise<TicketBulkPatchResponse> {
  const res = await fetch("/api/v1/tickets/_bulk/patch", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refs, patch }),
  });
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new ApiError(
      (b as { code?: string; message?: string }).code
        || (b as { message?: string }).message
        || "Bulk patch failed",
      res.status,
    );
  }
  return (await res.json()) as TicketBulkPatchResponse;
}
