import { useState, type FC, type ReactNode } from "react";
import HelpTooltip from "@/components/help-tooltip";

/**
 * Hero panel — the single large customizable region above the secondary
 * grid. Internal tabs let the operator switch between widget views
 * (current alerts, traffic flow, status, etc.) without leaving the page.
 *
 * Each tab declares its own render content + a required `help`
 * description. Same invariant as WidgetCard: every operator-visible
 * data surface must explain what it shows.
 */

export interface HeroTab {
  readonly id: string;
  readonly label: string;
  readonly subtitle?: string;
  readonly badge?: ReactNode;
  readonly content: ReactNode;
  /**
   * Operator-facing description of what this tab shows. Required.
   */
  readonly help: ReactNode;
}

export interface HeroPanelProps {
  readonly tabs: readonly HeroTab[];
  readonly initialTabId?: string;
}

export const HeroPanel: FC<HeroPanelProps> = ({ tabs, initialTabId }) => {
  const [active, setActive] = useState<string>(
    initialTabId ?? tabs[0]?.id ?? "",
  );
  const tab = tabs.find((t) => t.id === active) ?? tabs[0];

  return (
    <section
      aria-label="hero panel"
      className="mb-6 overflow-hidden rounded-lg border border-border bg-bg-surface"
    >
      <header className="flex flex-wrap items-end gap-2 border-b border-border bg-bg-card/50 px-4 pt-2">
        <nav className="flex flex-wrap items-end" role="tablist">
          {tabs.map((t) => {
            const isActive = t.id === tab?.id;
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                aria-controls={`tab-panel-${t.id}`}
                id={`tab-${t.id}`}
                tabIndex={isActive ? 0 : -1}
                onClick={() => setActive(t.id)}
                className={[
                  "relative -mb-px border-b-2 px-4 py-2 text-sm transition-colors",
                  isActive
                    ? "border-accent text-accent"
                    : "border-transparent text-text-secondary hover:border-border-bright hover:text-text-primary",
                ].join(" ")}
              >
                <span>{t.label}</span>
                {t.badge ? (
                  <span className="ml-2 align-middle">{t.badge}</span>
                ) : null}
              </button>
            );
          })}
        </nav>
        {tab?.help && (
          <span className="ml-auto pb-2">
            <HelpTooltip label={`About: ${tab.label}`} placement="bottom">
              {tab.help}
            </HelpTooltip>
          </span>
        )}
      </header>

      <div
        role="tabpanel"
        id={`tab-panel-${tab?.id ?? ""}`}
        aria-labelledby={`tab-${tab?.id ?? ""}`}
        className="p-5"
      >
        {tab?.subtitle ? (
          <p className="mb-3 text-xs text-text-dim">{tab.subtitle}</p>
        ) : null}
        {tab?.content}
      </div>
    </section>
  );
};

export default HeroPanel;
