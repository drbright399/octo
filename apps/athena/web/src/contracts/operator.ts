/**
 * Operator + role-tier shapes shared by the admin operator-management UI.
 *
 * Mirrors the server-side Pydantic models in
 * `octo_admin/api/routers/admin_ops.py` and the role-gate definitions in
 * `octo_admin/api/role_gates.py`. Keep field names in sync with the
 * server contract.
 *
 * Tier ordering (low → high): viewer (1) < analyst (2) < admin (3) < super_admin (4)
 */

export type RoleName = "super_admin" | "admin" | "analyst" | "viewer";

export const ROLE_TIER: Readonly<Record<RoleName, number>> = {
  viewer: 1,
  analyst: 2,
  admin: 3,
  super_admin: 4,
} as const;

export const ROLE_LABEL: Readonly<Record<RoleName, string>> = {
  super_admin: "Super-admin",
  admin: "Admin",
  analyst: "Analyst",
  viewer: "Viewer",
} as const;

export interface OperatorListEntry {
  id: number;
  username: string;
  email: string;
  roles: RoleName[];
  scope_slugs: string[];
  mfa_enabled: boolean;
  must_change_password: boolean;
  disabled_at: string | null;
  last_login_at: string | null;
  created_at: string;
  /** Slice 7f — factory super_admin marker. Read-only; can't be
   * changed from this surface. */
  is_factory: boolean;
  /** Slice 7f — admin/super_admin can toggle via setLlmGrant.
   * Operator's own preferences gate is separate (operator-controlled
   * in Settings → Account). */
  l2_llm_granted: boolean;
}

export interface CreateOperatorPayload {
  username: string;
  email: string;
  role: RoleName;
  scope_slugs?: string[];
  reason?: string;
}

export interface CreateOperatorResponse {
  operator_id: number;
  username: string;
  email: string;
  role: RoleName;
  state: "pending";
  activation_path: string;
  magic_link_url: string;
  magic_link_expires_at: string;
}

export interface MeResponse {
  operator_id: number;
  username: string;
  email: string;
  /** Friendly name set by the operator. Athena prefers this over `username`
   *  in user-facing strings (dropdown, dashboard greeting). null when unset. */
  display_name: string | null;
  /**
   * Server returns this as `role: list[str]` (singular name, plural value —
   * historical inconsistency in the auth.py contract). Field name MUST stay
   * `role` here to match the wire shape; the value is always an array.
   */
  role: RoleName[];
  scope_slugs: string[];
  /** Force first-login flow when true. */
  must_change_password: boolean;
  /** TOTP enrolled? Drives the MFA badge + the forced-setup gate. */
  mfa_enabled: boolean;
  /** Unconsumed backup codes in the active set. 0 if none generated. */
  backup_codes_remaining: number;
  /** Convenience: must_change_password OR !mfa_enabled. */
  needs_setup: boolean;
}

export function maxTier(roles: readonly RoleName[] | undefined | null): number {
  // Defensive against contract drift — if the wire field name changes or is
  // omitted, treat as zero-tier instead of crashing the SPA.
  if (roles == null || !Array.isArray(roles)) return 0;
  const safe: readonly RoleName[] = roles;
  return safe.reduce((max, r) => Math.max(max, ROLE_TIER[r] ?? 0), 0);
}

export function canManageRole(
  callerRoles: readonly RoleName[] | undefined | null,
  targetRole: RoleName,
): boolean {
  return maxTier(callerRoles) >= ROLE_TIER[targetRole];
}
