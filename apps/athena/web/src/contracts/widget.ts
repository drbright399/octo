/**
 * TypeScript mirror of `packages/shared-widget-contract` (Python).
 *
 * Stays in sync manually. Drift is caught by:
 *   - The render component IDs being a closed Literal union (compile-time).
 *   - A snapshot test that imports both contracts and asserts equality
 *     (planned: ships when the bridge wiring lands and we have a real
 *     fetch path).
 *
 * Contract version: 1.0
 */

export const WIDGET_CONTRACT_VERSION = "1.0" as const;

export type WidgetSize = "small" | "medium" | "large";

export type WidgetCategory =
  | "source-adapter"
  | "system"
  | "rmm"
  | "edr"
  | "mdr"
  | "network"
  | "compliance"
  | "fleet"
  | "octopus"
  | "custom";

export type OperatorRole = "super_admin" | "admin" | "analyst" | "viewer";

export type DefaultRenderComponent =
  | "default-alert-feed"
  | "default-counter-grid"
  | "default-time-series"
  | "default-list-with-actions"
  | "default-status-panel";

export const DEFAULT_RENDER_COMPONENTS: ReadonlySet<DefaultRenderComponent> =
  new Set([
    "default-alert-feed",
    "default-counter-grid",
    "default-time-series",
    "default-list-with-actions",
    "default-status-panel",
  ] as const);

export type ParamKind =
  | "bool"
  | "int"
  | "string"
  | "enum"
  | "duration_sec"
  | "severity_filter";

export interface ConfigurableParam {
  readonly name: string;
  readonly label: string;
  readonly kind: ParamKind;
  readonly description: string;
  readonly default_value: unknown;
  readonly enum_choices?: readonly string[];
  readonly min_value?: number;
  readonly max_value?: number;
}

export interface WidgetDefinition {
  readonly widget_id: string;
  readonly title: string;
  readonly description: string;
  readonly default_size: WidgetSize | readonly [number, number];
  readonly default_position: "top-left" | "top-right" | "auto";
  readonly data_query: string;
  readonly render_component_ref: string;
  readonly categories: readonly WidgetCategory[];
  readonly min_role: OperatorRole;
  readonly refresh_interval_sec: number;
  readonly configurable_params: readonly ConfigurableParam[];
  readonly framework_version_min: string;
  readonly contract_version: string;
}

/**
 * Result of a bridge query template execution. Mirror of
 * `shared_bridge.types.QueryResult`.
 */
export interface QueryResult<TRow = Record<string, unknown>> {
  readonly template_id: string;
  readonly rows: readonly TRow[];
  readonly row_count: number;
  readonly elapsed_ms: number;
  readonly audit_entry_id: number;
}
