/**
 * Conditional-field helpers for integration configure forms.
 *
 * Adapters can declare `show_when` / `required_when` on a credential field —
 * a map of sibling field name → the values of that field for which THIS field
 * is shown / required. Wazuh uses this so the connection-mode selector
 * (existing / import / bundled) drives which fields appear and validate
 * ("bundled" hides the manager URL + API key).
 */
import type { CredentialField } from "@/contracts/integration";

type Values = Record<string, string>;

function matches(
  cond: Readonly<Record<string, readonly string[]>> | null | undefined,
  values: Values,
): boolean {
  if (!cond) return true;
  return Object.entries(cond).every(([sibling, allowed]) =>
    allowed.includes(values[sibling] ?? ""),
  );
}

/** A field is visible unless its `show_when` excludes the current values. */
export function fieldVisible(field: CredentialField, values: Values): boolean {
  return matches(field.show_when, values);
}

/** A field is required per `required_when` if present, else its static flag. */
export function fieldRequired(field: CredentialField, values: Values): boolean {
  if (field.required_when) return matches(field.required_when, values);
  return field.required;
}

/** The fields to render, given current values (hides mode-excluded fields). */
export function visibleFields(
  fields: readonly CredentialField[],
  values: Values,
): CredentialField[] {
  return fields.filter((f) => fieldVisible(f, values));
}

/** True when every visible field that's required for the current mode is filled. */
export function allRequiredFilled(
  fields: readonly CredentialField[],
  values: Values,
): boolean {
  return visibleFields(fields, values).every(
    (f) => !fieldRequired(f, values) || (values[f.name]?.trim().length ?? 0) > 0,
  );
}

/**
 * The ONE recovery path for anything credential-shaped (credentials are
 * create-only). Worded identically everywhere it is described — and identical
 * to the backend's `webhook_auth.RECOVERY_PATH` — so the operator is always
 * sent to the same control: the "Disable" button on the integration's card.
 */
export function recoveryPath(vendorName: string): string {
  return `Settings → Integrations → ${vendorName} → Disable, then Add integration again`;
}
