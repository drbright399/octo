/**
 * Proposals API (admin+): Autotask addresses proposed as site locations —
 * list, refresh from Autotask, look one address up, confirm (with a reason)
 * or reject (with a reason). Cookies only; a dead session hard-redirects.
 */
import type {
  LocationProposal,
  ProposalRefreshResponse,
  ProposalSummary,
  ProposalsResponse,
} from "@/contracts/proposals";
import { call } from "@/lib/fleet";

export function fetchProposals(
  opts: { status?: "open" | "decided" | "all"; tenant?: string | null } = {},
): Promise<ProposalsResponse> {
  const q = new URLSearchParams({ kind: "site_location", status: opts.status ?? "open" });
  if (opts.tenant) q.set("tenant", opts.tenant);
  return call<ProposalsResponse>(`/api/v1/proposals?${q.toString()}`, {},
    "The proposed locations could not be loaded");
}

/** The open count (the Fleet page's badge). Quiet: never redirects. */
export function fetchProposalSummary(): Promise<ProposalSummary> {
  return call<ProposalSummary>("/api/v1/proposals/summary", {},
    "The proposed locations could not be counted", false);
}

export function refreshProposals(): Promise<ProposalRefreshResponse> {
  return call<ProposalRefreshResponse>("/api/v1/proposals/refresh",
    { method: "POST", body: JSON.stringify({ kind: "site_location" }) },
    "Autotask could not be read");
}

export function lookupProposal(id: number): Promise<{ proposal: LocationProposal; provider: string }> {
  return call<{ proposal: LocationProposal; provider: string }>(
    `/api/v1/proposals/${id}/lookup`, { method: "POST", body: "{}" },
    "The address could not be looked up");
}

/** A confirm names the site and what the operator reviewed — the
 *  proposal's `updated_at` and that site's own pin (`pin_set_at`, null =
 *  none): the server refuses (409) when either changed since. */
export interface ConfirmBody {
  match_index?: number;
  lat?: number;
  lng?: number;
  label?: string;
  target_key: string;
  reason: string;
  expected_updated_at: string;
  expected_pin_set_at: string | null;
}

export function confirmProposal(id: number, body: ConfirmBody): Promise<LocationProposal> {
  return call<LocationProposal>(`/api/v1/proposals/${id}/confirm`,
    { method: "POST", body: JSON.stringify(body) }, "The location could not be confirmed");
}

export function rejectProposal(id: number, reason: string): Promise<LocationProposal> {
  return call<LocationProposal>(`/api/v1/proposals/${id}/reject`,
    { method: "POST", body: JSON.stringify({ reason }) }, "The proposal could not be rejected");
}
