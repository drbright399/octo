/**
 * Incidents API (Tier Black slice 1) + the threat registries' admin calls.
 * Cookies only, nothing cached in storage. The routes enforce every role
 * rule; the console only hides what a role cannot use.
 */
import { call } from "@/lib/fleet";
import type {
  ClientDecisionResponse,
  ClientIncident,
  CloseChecklist,
  CloseCode,
  EvidenceWindow,
  IncidentDetail,
  IncidentOut,
  IncidentSummary,
} from "@/contracts/incidents";

const seg = (s: string): string => encodeURIComponent(s);
const url = (slug: string, id: number, action = ""): string =>
  `/api/v1/incidents/${seg(slug)}/${id}${action ? `/${action}` : ""}`;
const post = <T,>(path: string, body: object, fallback: string): Promise<T> =>
  call<T>(path, { method: "POST", body: JSON.stringify(body) }, fallback);

/** `quiet`: a dead session is just an error (the strip polls on every
 *  route, the login page included — it must never redirect). */
export function fetchIncidentSummary(opts: { quiet?: boolean } = {}): Promise<IncidentSummary> {
  return call<IncidentSummary>("/api/v1/incidents/summary", {},
    "The incident summary could not be loaded", !opts.quiet);
}

export function fetchIncident(slug: string, id: number): Promise<IncidentDetail> {
  return call<IncidentDetail>(url(slug, id), {}, "The incident could not be loaded");
}

export function ackIncident(slug: string, id: number, note?: string): Promise<IncidentOut> {
  return post<IncidentOut>(url(slug, id, "ack"), note ? { note } : {},
    "The incident could not be acknowledged");
}

export function noteIncident(slug: string, id: number, text: string): Promise<IncidentOut> {
  return post<IncidentOut>(url(slug, id, "note"), { text }, "The note could not be saved");
}

export function containIncident(slug: string, id: number, receipt: string): Promise<IncidentOut> {
  return post<IncidentOut>(url(slug, id, "contain"), { receipt },
    "The incident could not be marked contained");
}

export function raiseIncident(slug: string, id: number, reason: string): Promise<IncidentOut> {
  return post<IncidentOut>(url(slug, id, "raise"), { reason }, "The incident could not be raised");
}

export function closeIncident(
  slug: string, id: number, body: { code: CloseCode; text: string; checklist?: CloseChecklist },
): Promise<IncidentOut> {
  return post<IncidentOut>(url(slug, id, "close"), body, "The incident could not be closed");
}

export function lockdownRequest(slug: string, id: number, note: string): Promise<unknown> {
  return post(url(slug, id, "lockdown-request"), { note },
    "The lockdown request could not be recorded");
}

export function answerDecision(
  slug: string, id: number, decisionId: number, confirm: boolean, note: string,
): Promise<unknown> {
  return post(url(slug, id, `decisions/${decisionId}/answer`), { confirm, note },
    "The answer could not be recorded");
}

export function assignIncident(slug: string, id: number, to: number): Promise<IncidentOut> {
  return post<IncidentOut>(url(slug, id, "assign"), { to }, "The incident could not be assigned");
}

/** admin+, step-up: close a Black as reclassified — the Black stays Black
 *  (closed) and a LINKED Red opens. Never a lowering in place. */
export function reclassifyIncident(slug: string, id: number, reason: string): Promise<unknown> {
  return post(url(slug, id, "reclassify"), { reason }, "The incident could not be reclassified");
}

// ---- evidence windows (Rick, 2026-10-05) — the former legal hold ----------

/** "2026-09-01 08:00 UTC" — evidence windows are typed and shown in UTC. */
export function utc(iso: string): string {
  return `${iso.replace("T", " ").slice(0, 16)} UTC`;
}

/** One window as a line: its span, and what it keeps. */
export function windowLine(w: EvidenceWindow): string {
  const end = w.end ? utc(w.end)
    : w.kind === "incident" ? "open (until the all-clear)" : "open (until released)";
  const kept = w.kept_rows === null ? "rows kept: not counted yet"
    : `${w.kept_rows.toLocaleString("en-US")} row${w.kept_rows === 1 ? "" : "s"} kept past retention`;
  const events = w.events_in_window === null ? ""
    : ` · ~${w.events_in_window.toLocaleString("en-US")}${w.events_capped ? "+" : ""} events`;
  return `${utc(w.start)} → ${end} · ${kept}${events}`;
}

/** admin+ with step-up: a NEW manual window (an explicit start, an optional
 *  end — none = held open until released), or — `window_id` — EXTEND one
 *  (start earlier / end later; never a shrink). Times are UTC. */
export function addEvidenceWindow(
  slug: string, id: number,
  body: { start: string; end?: string; reason: string; window_id?: number },
): Promise<EvidenceWindow> {
  return post<EvidenceWindow>(url(slug, id, "evidence-window"), body,
    "The evidence window could not be saved");
}

/** analyst+: an EARLIER start (dwell time found later), with a reason. */
export function widenEvidenceWindow(
  slug: string, id: number, windowId: number, start: string, reason: string,
): Promise<EvidenceWindow> {
  return post<EvidenceWindow>(url(slug, id, `evidence-window/${windowId}/widen`),
    { start, reason }, "The evidence window could not be widened");
}

/** admin+ with step-up, after the all-clear only: the other admins are told. */
export function releaseEvidenceWindow(
  slug: string, id: number, windowId: number, reason: string,
): Promise<EvidenceWindow> {
  return post<EvidenceWindow>(url(slug, id, `evidence-window/${windowId}/release`),
    { reason }, "The evidence window could not be released");
}

export async function fetchEvidenceWindows(
  state: "held" | "released" | "all" = "held",
): Promise<EvidenceWindow[]> {
  const r = await call<{ items: EvidenceWindow[] }>(
    `/api/v1/incidents/evidence-windows?state=${state}`, {},
    "The evidence windows could not be loaded");
  return Array.isArray(r.items) ? r.items : [];
}

/** B6 — "the client calls: someone is controlling my screen". */
export function declareBlack(body: {
  tenant: string; summary: string; reason: string; site_key?: string; device_ref?: string;
  device_label?: string;
}): Promise<IncidentOut> {
  return post<IncidentOut>("/api/v1/incidents/declare", body, "The incident could not be declared");
}

/** R8 — "Confirm as threat" on a signal: RED, a reason of ≥ 20 characters. */
export const CONFIRM_REASON_MIN = 20;

export function confirmSignal(slug: string, eventId: number, reason: string):
  Promise<IncidentOut> {
  return post<IncidentOut>(`/api/v1/signals/${seg(slug)}/${eventId}/confirm`, { reason },
    "The signal could not be confirmed as a threat");
}

// ---- the client (viewer) surface -----------------------------------------

export async function fetchClientIncidents(): Promise<ClientIncident[]> {
  const r = await call<{ items: ClientIncident[] }>("/api/v1/incidents/client", {},
    "Your security incidents could not be loaded");
  return r.items;
}

export function clientDecision(
  ref: string, kind: "lockdown" | "allow",
): Promise<ClientDecisionResponse> {
  return post<ClientDecisionResponse>(`/api/v1/incidents/client/${seg(ref)}/decision`, { kind },
    "Your decision could not be recorded");
}

// ---- restricted incidents (B7, CSAM) — the MSP's client-notice switch -----

export interface RestrictedSettings {
  /** May a client user read the neutral line of a restricted incident?
   *  OFF by default (suppressed). */
  csam_client_notice: boolean;
  help: string;
}

export function fetchRestrictedSettings(): Promise<RestrictedSettings> {
  return call<RestrictedSettings>("/api/v1/admin/tiers/restricted", {},
    "The restricted-incident setting could not be loaded");
}

/** admin+ with an all-tenant scope; audited on the server BEFORE the write,
 *  the other admins told. */
export function putRestrictedSettings(on: boolean, reason: string): Promise<RestrictedSettings> {
  return call<RestrictedSettings>("/api/v1/admin/tiers/restricted",
    { method: "PUT", body: JSON.stringify({ csam_client_notice: on, reason }) },
    "The restricted-incident setting could not be saved");
}

// ---- the threat registries (admin UI) ------------------------------------

export interface AssetTag {
  id: number;
  tenant_slug: string;
  ref_kind: "device" | "path";
  device_ref: string;
  tag: string;
  set_by: number;
  set_at: string;
  reason: string;
}

export const ASSET_TAGS = ["life_safety", "cjis", "patient_care", "critical_24x7", "server",
  "dc", "lab", "evidence_hold", "dev", "kiosk", "hands_off"] as const;

export async function fetchAssetTags(tenant?: string): Promise<AssetTag[]> {
  const q = tenant ? `?tenant=${seg(tenant)}` : "";
  const r = await call<{ tags: AssetTag[] }>(`/api/v1/admin/registry/asset-tags${q}`, {},
    "The asset tags could not be loaded");
  return r.tags;
}

export function addAssetTag(body: {
  tenant: string; ref_kind: "device" | "path"; device_ref: string; tag: string; reason: string;
}): Promise<{ tags: AssetTag[] }> {
  return post("/api/v1/admin/registry/asset-tags", body, "The tag could not be saved");
}

export function clearAssetTag(id: number, reason: string): Promise<{ tags: AssetTag[] }> {
  return post(`/api/v1/admin/registry/asset-tags/${id}/clear`, { reason },
    "The tag could not be cleared");
}

export type RegistryTable = "exceptions" | "verdicts" | "remote-access" | "canary-allowlist";

export async function fetchRegistry(table: RegistryTable): Promise<Record<string, unknown>[]> {
  const r = await call<{ rows: Record<string, unknown>[] }>(`/api/v1/admin/registry/${table}`, {},
    "The registry could not be loaded");
  return r.rows;
}

export function addException(body: {
  tenant: string; binding_kind: string; binding: string; rule_id: string; days: number;
  reason: string;
}): Promise<unknown> {
  return post("/api/v1/admin/registry/exceptions", body, "The exception could not be saved");
}

export function addAllowlist(body: { tenant: string; ip: string; label: string; reason: string }):
  Promise<unknown> {
  return post("/api/v1/admin/registry/canary-allowlist", body,
    "The allowlist entry could not be saved");
}

export interface RuleRow {
  id: string;
  version: number;
  tier: string;
  stage: string;
  kind: string;
  title: string;
  inputs: string[];
  description: string;
  braked_until: string | null;
  coverage: Record<string, { covered: boolean; missing: string[] }>;
  /** A restricted rule (B7, CSAM): admin-only incidents; never braked. */
  restricted?: boolean;
}

export async function fetchRules(): Promise<RuleRow[]> {
  const r = await call<{ rules: RuleRow[] }>("/api/v1/tiers/rules", {},
    "The tier rules could not be loaded");
  return r.rules;
}

export async function fetchBrakes(): Promise<Record<string, unknown>[]> {
  const r = await call<{ brakes: Record<string, unknown>[] }>("/api/v1/admin/tiers/brake", {},
    "The brakes could not be loaded");
  return r.brakes;
}

export function setBrake(body: { rule_id: string; hours: number; reason: string }):
  Promise<unknown> {
  return post("/api/v1/admin/tiers/brake", body, "The brake could not be set");
}
