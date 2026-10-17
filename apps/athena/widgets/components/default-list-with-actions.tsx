/**
 * `default-list-with-actions` — vertical list of rows, each with a label
 * and one or more inline actions. Use cases: device list with isolate /
 * inspect / acknowledge buttons, integrations summary with reconnect /
 * disable, etc.
 *
 * Action buttons are wired by the caller; the component itself never
 * mutates state.
 *
 * An action is HONEST about whether it does anything:
 *   - `href(row)` → rendered as a new-tab link (rel="noopener noreferrer")
 *     for rows where it returns an https URL;
 *   - `resolveHref(row)` → for a target whose address must be LOOKED UP when
 *     the operator asks (a vendor API read): a button that resolves on click,
 *     opens the result in a new tab, and shows the reason when it cannot
 *     (see ResolvedLinkButton). Rows where it returns undefined have nothing
 *     to open;
 *   - `disabled` (a boolean, or per row) → a disabled button whose tooltip is
 *     `disabledReason`. A button that looks live and does nothing is a bug.
 */

import type { ReactNode } from "react";

import { ResolvedLinkButton } from "./resolved-link-button";

export interface ListAction<T> {
  readonly id: string;
  readonly label: string;
  /** Click handler. Ignored for rows where `href` yields a link. */
  readonly onPerform?: (row: T) => void;
  /** External target for this row; undefined = no link for this row. */
  readonly href?: (row: T) => string | undefined;
  /** A target resolved on click: returns the row's lookup, or undefined when
   *  this row has nothing to look up. The lookup rejects with the sentence to
   *  show; nothing is opened then. */
  readonly resolveHref?: (row: T) => (() => Promise<string>) | undefined;
  readonly tone?: "default" | "danger" | "accent";
  readonly disabled?: boolean | ((row: T) => boolean);
  /** Tooltip shown on the disabled button — say WHY. */
  readonly disabledReason?: string | ((row: T) => string | undefined);
  /** Tooltip for the enabled control. */
  readonly title?: string | ((row: T) => string | undefined);
}

export interface ListRow {
  readonly id: string;
  readonly title: string;
  readonly subtitle?: string;
  readonly meta?: ReactNode;
}

export interface DefaultListWithActionsProps<T extends ListRow = ListRow> {
  readonly rows: readonly T[];
  readonly actions: readonly ListAction<T>[];
  readonly emptyLabel?: string;
}

const TONE_CLASS: Record<NonNullable<ListAction<ListRow>["tone"]>, string> = {
  default: "text-text-secondary hover:text-text-primary",
  danger: "text-critical hover:text-critical",
  accent: "text-accent hover:text-accent-strong",
};

const BASE_CLASS =
  "rounded-sm border border-border bg-bg-input px-2.5 py-1 text-[11px] transition-colors hover:border-border-bright hover:bg-accent-soft";

function resolve<T, V>(value: V | ((row: T) => V) | undefined, row: T): V | undefined {
  return typeof value === "function" ? (value as (row: T) => V)(row) : value;
}

export function DefaultListWithActions<T extends ListRow>({
  rows,
  actions,
  emptyLabel = "Nothing here yet.",
}: DefaultListWithActionsProps<T>): ReactNode {
  if (rows.length === 0) {
    return (
      <div className="px-4 py-6 text-center text-sm italic text-text-dim">
        {emptyLabel}
      </div>
    );
  }
  return (
    <ul className="flex flex-col gap-2" role="list">
      {rows.map((row) => (
        <li
          key={row.id}
          className="nav-sweep flex flex-wrap items-center gap-3 rounded border border-border bg-bg-card px-3 py-2"
        >
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-medium text-text-primary">
              {row.title}
            </div>
            {row.subtitle ? (
              <div className="truncate font-mono text-[11px] text-text-secondary">
                {row.subtitle}
              </div>
            ) : null}
          </div>
          {row.meta ? (
            <div className="font-mono text-[11px] text-text-dim">{row.meta}</div>
          ) : null}
          <div className="flex shrink-0 gap-1.5">
            {actions.map((action) => {
              const tone = TONE_CLASS[action.tone ?? "default"];
              const disabled = Boolean(resolve(action.disabled, row));
              const href = disabled ? undefined : action.href?.(row);
              if (href && href.startsWith("https://")) {
                return (
                  <a
                    key={action.id}
                    href={href}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={resolve(action.title, row)}
                    className={[BASE_CLASS, tone].join(" ")}
                  >
                    {action.label} <span aria-hidden="true">↗</span>
                  </a>
                );
              }
              const lookup = disabled ? undefined : action.resolveHref?.(row);
              if (lookup) {
                return (
                  <ResolvedLinkButton
                    key={action.id}
                    label={action.label}
                    resolve={lookup}
                    title={resolve(action.title, row)}
                    testId={`list-action-${action.id}`}
                    className={[BASE_CLASS, tone].join(" ")}
                  />
                );
              }
              // No link for this row and no handler → nothing it could do.
              const inert =
                disabled ||
                ((action.href !== undefined || action.resolveHref !== undefined) &&
                  !action.onPerform);
              return (
                <button
                  key={action.id}
                  type="button"
                  disabled={inert}
                  title={
                    inert
                      ? resolve(action.disabledReason, row)
                      : resolve(action.title, row)
                  }
                  onClick={() => action.onPerform?.(row)}
                  className={[
                    BASE_CLASS,
                    tone,
                    inert ? "cursor-not-allowed opacity-50" : "",
                  ].join(" ")}
                >
                  {action.label}
                </button>
              );
            })}
          </div>
        </li>
      ))}
    </ul>
  );
}

export default DefaultListWithActions;
