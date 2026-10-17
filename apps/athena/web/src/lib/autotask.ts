/**
 * Autotask integration API client (P4-b1 + P4-b2).
 *
 * super_admin endpoints. Used by the Settings → Integrations →
 * Autotask Mappings page to manage operator↔resource +
 * tenant↔company mappings, plus the proxy endpoints that fetch
 * Companies + Resources lists from the live Autotask instance.
 */
import { ApiError } from "@/lib/api";

export interface OperatorMapping {
  operator_id: number;
  autotask_resource_id: number;
  autotask_resource_email: string | null;
  autotask_resource_name: string | null;
  updated_at: string | null;
  updated_by_operator_id: number | null;
}

export interface TenantMapping {
  tenant_slug: string;
  autotask_company_id: number;
  autotask_company_name: string | null;
  autotask_homepage_url: string | null;
  updated_at: string | null;
  updated_by_operator_id: number | null;
}

export interface AutotaskCompanyOption {
  id: number;
  name: string | null;
}

export interface AutotaskResourceOption {
  id: number;
  email: string | null;
  name: string | null;
}

async function _json<T>(res: Response, fallbackMsg: string): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      (body as { code?: string; message?: string }).code
        || (body as { message?: string }).message
        || fallbackMsg,
      res.status,
    );
  }
  return (await res.json()) as T;
}

export async function getOperatorMappings(
  instanceId: number,
): Promise<OperatorMapping[]> {
  const res = await fetch(
    `/api/v1/integrations/autotask/${instanceId}/mappings/operators`,
    { credentials: "include" },
  );
  const body = await _json<{ mappings: OperatorMapping[] }>(
    res, "Failed to load operator mappings",
  );
  return body.mappings;
}

export async function putOperatorMappings(
  instanceId: number,
  mappings: Array<{
    operator_id: number;
    autotask_resource_id: number;
    autotask_resource_email?: string | null;
    autotask_resource_name?: string | null;
  }>,
): Promise<OperatorMapping[]> {
  const res = await fetch(
    `/api/v1/integrations/autotask/${instanceId}/mappings/operators`,
    {
      method: "PUT",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mappings }),
    },
  );
  const body = await _json<{ mappings: OperatorMapping[] }>(
    res, "Failed to save operator mappings",
  );
  return body.mappings;
}

export async function getTenantMappings(
  instanceId: number,
): Promise<TenantMapping[]> {
  const res = await fetch(
    `/api/v1/integrations/autotask/${instanceId}/mappings/companies`,
    { credentials: "include" },
  );
  const body = await _json<{ mappings: TenantMapping[] }>(
    res, "Failed to load tenant mappings",
  );
  return body.mappings;
}

export async function putTenantMappings(
  instanceId: number,
  mappings: Array<{
    tenant_slug: string;
    autotask_company_id: number;
    autotask_company_name?: string | null;
    autotask_homepage_url?: string | null;
  }>,
): Promise<TenantMapping[]> {
  const res = await fetch(
    `/api/v1/integrations/autotask/${instanceId}/mappings/companies`,
    {
      method: "PUT",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mappings }),
    },
  );
  const body = await _json<{ mappings: TenantMapping[] }>(
    res, "Failed to save tenant mappings",
  );
  return body.mappings;
}

export async function listAutotaskCompanies(
  instanceId: number,
): Promise<AutotaskCompanyOption[]> {
  const res = await fetch(
    `/api/v1/integrations/autotask/${instanceId}/companies`,
    { credentials: "include" },
  );
  const body = await _json<{ items: AutotaskCompanyOption[] }>(
    res, "Failed to fetch Autotask companies",
  );
  return body.items;
}

export async function listAutotaskResources(
  instanceId: number,
): Promise<AutotaskResourceOption[]> {
  const res = await fetch(
    `/api/v1/integrations/autotask/${instanceId}/resources`,
    { credentials: "include" },
  );
  const body = await _json<{ items: AutotaskResourceOption[] }>(
    res, "Failed to fetch Autotask resources",
  );
  return body.items;
}
