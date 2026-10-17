/**
 * Incidents — Red and Black (`/api/v1/incidents`, Tier Black slice 1).
 *
 * Operators (analyst+) read and act on incidents; a CLIENT user (viewer)
 * gets only the neutral summary and their own visible incidents with
 * exactly two actions ("Lock down my network and contact my analyst" /
 * "Allow this traffic") — recorded only in slice 1, never executed.
 * There is NO lower / mute / snooze anywhere: only a person closes.
 */

import type { ThreatItem } from "@/contracts/fleet";

export type IncidentTier = "red" | "black";

/** The global strip (every route, 15 s). A client user never gets
 *  `black_unacked` or `items` (no pulse, no detail). */
export interface IncidentSummary {
  view: "operator" | "client";
  black: number;
  red: number;
  black_unacked?: number;
  items?: ThreatItem[];
  /** A client user: the worst neutral line of what they may see ("…has
   *  been alerted", "…is responding", "…contained…", "…under investigation…"). */
  status_neutral?: string | null;
}

export interface IncidentOut {
  tenant_slug: string;
  tenant_name: string;
  id: number;
  tier: IncidentTier;
  status: string;
  open: boolean;
  rule_id: string;
  rule_version: number;
  rule_title: string;
  summary: string;
  opened_at: string;
  age_s: number;
  site_key: string | null;
  device_ref: string | null;
  device_label: string | null;
  scope: string;
  acked: boolean;
  acked_by: string | null;
  acked_by_name: string | null;
  acknowledged_at: string | null;
  assigned_to: string | null;
  assigned_to_name: string | null;
  contained: boolean;
  contained_at: string | null;
  closed_at: string | null;
  close_reason_code: string | null;
  reclassified_from: number | null;
  reopened_count: number;
  escalation_step: number;
  client_visible: boolean;
  opened_by: string | null;
  /** A Black contained for over 72 h with no new evidence: "ready to close?". */
  ready_to_close?: boolean;
  /** An evidence window of this incident is held: everything of the client
   *  inside it is kept by every retention path until an admin releases it. */
  evidence_held?: boolean;
  /** A RESTRICTED incident (B7, CSAM): admin / super_admin only. Anyone else
   *  reads "Restricted incident" at the tenant and nothing more. */
  restricted?: boolean;
}

/** One lookup of a restricted incident — the domain DEFANGED, never a link. */
export interface RestrictedLookup {
  id: number;
  category: string;
  source: string;
  observed_at: string;
  received_at: string;
  profile_id: string | null;
  device_key: string | null;
  device_name: string | null;
  client_ip: string | null;
  domain_defanged: string;
  root_defanged: string;
  reasons: string[];
  record_sha256: string;
}

/** The admin-only part of a restricted incident's (audited) detail. */
export interface RestrictedDetail {
  category: string;
  /** "DO NOT OPEN — do not visit, resolve or investigate the content". */
  warning: string;
  /** The fixed checklist (plain text). */
  checklist: string[];
  lookups: number;
  first_at: string | null;
  last_at: string | null;
  /** The MSP's switch: does the client see the neutral line? */
  client_notice: boolean;
  evidence: RestrictedLookup[];
  /** Other sensors' records naming the same domain (a buoy's Pi-hole /
   *  Suricata) — hidden from every other view; defanged here. */
  related?: RestrictedRelated[];
}

/** Another sensor's record of a restricted lookup — defanged, never a link. */
export interface RestrictedRelated {
  event_id: number;
  received_at: string;
  source: string;
  event_type: string;
  source_host: string | null;
  summary_defanged: string;
  /** The sensor's own record, clipped — defanged. */
  payload_defanged?: string;
}

/**
 * An EVIDENCE WINDOW (Rick, 2026-10-05: "if a threat is confirmed everything
 * from first detection up until the all clear should be treated as event
 * evidence"). A Red / Black opens one automatically (kind `incident`); an
 * admin may add one (kind `manual` — the former legal hold). Operators only:
 * a client user never sees one.
 */
export interface EvidenceWindow {
  id: number;
  tenant_slug: string;
  tenant_name: string;
  incident_id: number;
  origin_incident_id: number;
  incident_tier: IncidentTier | null;
  incident_status: string | null;
  incident_open: boolean | null;
  incident_summary: string | null;
  kind: "incident" | "manual";
  start: string;
  /** null = open: until the incident's all-clear (automatic) or until an
   *  admin releases it (a manual window without an end). */
  end: string | null;
  open: boolean;
  held: boolean;
  opened_by: string;
  opened_by_name: string | null;
  opened_at: string;
  reason: string;
  released_at: string | null;
  released_by: string | null;
  released_by_name: string | null;
  release_reason: string | null;
  /** Rows the last nightly retention run kept past their normal retention
   *  because of this window (null: not counted yet). */
  kept_rows: number | null;
  kept_counted_at: string | null;
  /** About how many events arrived inside it (capped; null: not cheap). */
  events_in_window: number | null;
  events_capped: boolean;
}

export interface IncidentDecision {
  id: number;
  incident_id: number;
  kind: "lockdown" | "allow";
  requested_by: string;
  requested_role: "client" | "analyst";
  tier_at_request: IncidentTier;
  status: "recorded" | "pending_analyst" | "confirmed" | "declined";
  scope: { kind: string; ref: string }[];
  /** Life-safety assets carved out — and targets that could not be checked
   *  against them (`unverified`: an analyst confirms first). */
  excluded: { kind: string; ref: string; tag?: string; why?: string; unverified?: boolean;
              matched?: boolean }[];
  notice: string;
  note: string | null;
  created_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  executed: number;
}

export interface IncidentDetail {
  incident: IncidentOut;
  timeline: { id: number; author: string; kind: string; text: string; created_at: string }[];
  evidence: { event_id: number; role: string; added_at: string; source?: string | null;
              event_type?: string | null; received_at?: string | null }[];
  snapshot: Record<string, unknown>;
  stages: Record<string, unknown>[];
  why: { condition: string; met: boolean; detail?: string | null; event_ids?: number[] }[];
  ruled_out: { check: string; ok: boolean }[];
  ruled_out_note: string | null;
  kill_chain: { phase: string; seen: boolean }[];
  coverage: { rule_id: string; covered: boolean; missing: string[] }[];
  mode: { mode: string; source: string; caps: string[] };
  proposed_steps: string[];
  decisions: IncidentDecision[];
  client_view: ClientIncident | null;
  asset_tags: string[];
  /** "Why this device?" — how the incident came to name its device. */
  why_device?: string[];
  /** The per-source freshness matrix frozen at open. */
  freshness?: FreshnessRow[];
  /** The incident's evidence windows (owned, or opened by it), newest first. */
  evidence_windows?: EvidenceWindow[];
  /** A RESTRICTED incident (B7, CSAM), admins only — the warning, the
   *  checklist, the lookups (defanged). */
  restricted?: RestrictedDetail | null;
}

export interface FreshnessRow {
  source: string;
  label: string;
  last_ok_at: string | null;
  failing_since: string | null;
  blind: boolean;
}

/** One incident as a client user sees it. */
export interface ClientIncident {
  ref: string;
  tier: IncidentTier | null;
  status_neutral: string;
  opened_at: string;
  actions: { kind: "lockdown" | "allow"; label: string }[];
  decisions: { kind: "lockdown" | "allow"; status: string; created_at: string;
               confirmation: string }[];
}

export interface ClientDecisionResponse {
  confirmation: string;
  decision: { kind: "lockdown" | "allow"; status: string; created_at: string };
}

export interface CloseChecklist {
  c2_blocked: "yes" | "n/a";
  rescue_point_verified: boolean;
  device_state: string;
  client_notified_who: string;
  client_notified_when: string;
}

export type CloseCode = "remediated" | "authorized_activity" | "duplicate" | "false_positive";
