/**
 * Entity resolution API (`/api/v1/entity/*`, `/api/v1/admin/known-benign`).
 * Cookies only (credentials: "include"); nothing is cached in storage. A 401
 * from a dead console session hard-redirects to /login.
 */
import { ApiError } from "@/lib/api";
import type {
  EntityMode,
  EntityStatus,
  KnownBenignInput,
  KnownBenignRule,
  Resolution,
  ReviewQueue,
} from "@/contracts/entity";

async function call<T>(url: string, init: RequestInit = {}, fallback = "Request failed"): Promise<T> {
  const opts: RequestInit = { credentials: "include", cache: "no-store", ...init };
  if (init.body) {
    opts.headers = { "Content-Type": "application/json" };
  }
  const res = await fetch(url, opts);
  const body = (await res.json().catch(() => ({}))) as { message?: string; code?: string };
  if (res.status === 401 && (body.code ?? "").startsWith("AUTH_SESSION_")) {
    window.location.href = "/login";
    throw new ApiError("Your session has expired — signing in again", 401, body.code);
  }
  if (!res.ok) {
    throw new ApiError(body.message || fallback, res.status, body.code);
  }
  return body as T;
}

const seg = (s: string): string => encodeURIComponent(s);

export function getResolution(slug: string, eventId: number): Promise<Resolution> {
  return call<Resolution>(`/api/v1/entity/${seg(slug)}/events/${eventId}/resolution`, {},
    "The resolution could not be loaded");
}

export function resolveNow(slug: string, eventId: number): Promise<Resolution> {
  return call<Resolution>(`/api/v1/entity/${seg(slug)}/events/${eventId}/resolve`,
    { method: "POST" }, "The alert could not be resolved");
}

export function getEntityStatus(slug: string): Promise<EntityStatus> {
  return call<EntityStatus>(`/api/v1/entity/${seg(slug)}/status`, {}, "Status unavailable");
}

export function setEntityMode(slug: string, mode: EntityMode, reason: string): Promise<{ mode: EntityMode }> {
  return call(`/api/v1/entity/${seg(slug)}/mode`,
    { method: "PUT", body: JSON.stringify({ mode, reason }) }, "The switch could not be changed");
}

export function getReviewQueue(slug: string): Promise<ReviewQueue> {
  return call<ReviewQueue>(`/api/v1/entity/${seg(slug)}/review`, {}, "The review queue could not be loaded");
}

export function confirmLink(slug: string, kind: "site" | "device", id: number, reason?: string): Promise<unknown> {
  return call(`/api/v1/entity/${seg(slug)}/links/${kind}/${id}/confirm`,
    { method: "POST", body: JSON.stringify(reason ? { reason } : {}) }, "Not confirmed");
}

export function rejectLink(slug: string, kind: "site" | "device", id: number, reason: string): Promise<unknown> {
  return call(`/api/v1/entity/${seg(slug)}/links/${kind}/${id}/reject`,
    { method: "POST", body: JSON.stringify({ reason }) }, "Not rejected");
}

export function resolveConflict(slug: string, id: number, reason: string): Promise<unknown> {
  return call(`/api/v1/entity/${seg(slug)}/conflicts/${id}/resolve`,
    { method: "POST", body: JSON.stringify({ reason }) }, "Not resolved");
}

export function acceptConflict(slug: string, id: number, reason: string): Promise<unknown> {
  return call(`/api/v1/entity/${seg(slug)}/conflicts/${id}/accept`,
    { method: "POST", body: JSON.stringify({ reason }) }, "Not accepted");
}

export function reopenConflict(slug: string, id: number, reason: string): Promise<unknown> {
  return call(`/api/v1/entity/${seg(slug)}/conflicts/${id}/reopen`,
    { method: "POST", body: JSON.stringify({ reason }) }, "Not reopened");
}

export function listKnownBenign(): Promise<KnownBenignRule[]> {
  return call<KnownBenignRule[]>("/api/v1/admin/known-benign", {}, "The rules could not be loaded");
}

export function createKnownBenign(rule: KnownBenignInput): Promise<KnownBenignRule[]> {
  return call<KnownBenignRule[]>("/api/v1/admin/known-benign",
    { method: "POST", body: JSON.stringify(rule) }, "The rule was not saved");
}

export function updateKnownBenign(id: number, rule: KnownBenignInput): Promise<KnownBenignRule[]> {
  return call<KnownBenignRule[]>(`/api/v1/admin/known-benign/${id}`,
    { method: "PUT", body: JSON.stringify(rule) }, "The rule was not saved");
}
