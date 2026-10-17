import { type FC, type ReactNode } from "react";
import { useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import HelpTooltip from "@/components/help-tooltip";

/**
 * Widget card — chrome for one tile in the secondary grid.
 *
 * Two render modes:
 *   - locked (default): clean tile, just title + help icon + content
 *   - customizing: whole card is a drag handle (cursor: grab); ▾ minimize
 *     and ✕ close buttons visible in the header
 *
 * Minimize: when toggled on, the parent dashboard re-renders this card
 * into the "minimized tray" below the grid (a compact pill row). The
 * card itself does NOT render the minimized state — that's the parent's
 * job. This keeps grid layout clean.
 *
 * Every widget MUST declare a `help` description.
 */

export interface WidgetCardProps {
  readonly id: string;
  readonly title: string;
  readonly subtitle?: string;
  readonly badge?: ReactNode;
  readonly help: ReactNode;
  readonly children: ReactNode;

  // Customize-mode
  readonly customizing?: boolean;
  readonly onMinimize?: () => void;
  readonly onClose?: () => void;
  /** Pinned widgets cannot be reordered or hidden, only minimized. */
  readonly pinned?: boolean;
}

export const WidgetCard: FC<WidgetCardProps> = ({
  id,
  title,
  subtitle,
  badge,
  help,
  children,
  customizing = false,
  onMinimize,
  onClose,
  pinned = false,
}) => {
  const draggable = !!customizing && !pinned;

  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id,
    disabled: !draggable,
  });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.4 : undefined,
    zIndex: isDragging ? 50 : undefined,
  };

  // When draggable, spread the dnd-kit attrs + listeners on the whole
  // article. Inner buttons (minimize/close, help tooltip) keep their
  // own onClick which dnd-kit's PointerSensor distinguishes from drag
  // via its activationConstraint distance threshold.
  const dragProps = draggable ? { ...attributes, ...listeners } : {};

  return (
    <article
      ref={setNodeRef}
      style={style}
      data-widget-id={id}
      {...dragProps}
      className={[
        // h-full so the card fills its react-grid-layout cell; without
        // this the article shrinks to its content's natural height and
        // leaves an empty gap inside the grid cell.
        "flex h-full flex-col rounded-lg border bg-bg-surface select-none overflow-hidden",
        customizing && !pinned
          ? "cursor-grab border-border-bright shadow-sm active:cursor-grabbing"
          : "border-border",
        pinned && customizing ? "border-accent/40" : "",
        isDragging ? "cursor-grabbing" : "",
      ].join(" ")}
    >
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          {customizing && !pinned && (
            <span
              aria-hidden="true"
              title="Drag from anywhere on this card"
              className="select-none text-text-dim"
            >
              ⋮⋮
            </span>
          )}
          {customizing && pinned && (
            <span
              aria-hidden="true"
              title="Pinned — always visible"
              className="select-none text-accent"
            >
              📌
            </span>
          )}
          <h3 className="flex min-w-0 items-center gap-2 text-xs font-semibold uppercase tracking-wider text-text-secondary">
            <span className="truncate">{title}</span>
            {badge}
            <HelpTooltip label={`About: ${title}`} placement="bottom">
              {help}
            </HelpTooltip>
          </h3>
        </div>
        {/* Inner buttons MUST stop propagation so the drag activation
            doesn't fire when the user clicks them. */}
        <div
          className="flex items-center gap-1"
          onPointerDown={(e) => e.stopPropagation()}
        >
          {onMinimize && (
            <button
              type="button"
              onClick={onMinimize}
              aria-label={`Minimize ${title}`}
              title="Minimize to tray"
              className="rounded-sm p-1 text-text-dim transition-colors hover:bg-accent-soft hover:text-accent"
            >
              ▾
            </button>
          )}
          {customizing && !pinned && onClose && (
            <button
              type="button"
              onClick={onClose}
              aria-label={`Hide ${title}`}
              title="Hide widget"
              className="rounded-sm p-1 text-text-dim transition-colors hover:bg-critical/10 hover:text-critical"
            >
              ✕
            </button>
          )}
        </div>
      </header>
      {/* min-h-0 lets the flex child shrink past its content; combined
          with overflow-y-auto this means widget content (alert feeds,
          ticket lists, etc.) scrolls *inside* the card when it
          overflows the resized card height, rather than pushing the
          whole grid taller. */}
      <div className="flex-1 min-h-0 overflow-y-auto p-3">{children}</div>
      {subtitle ? (
        <footer className="border-t border-border/40 px-3 py-1.5 text-[10px] text-text-dim">
          {subtitle}
        </footer>
      ) : null}
    </article>
  );
};

/**
 * Compact pill for the minimized tray. Lives below the main grid; clicking
 * the chevron restores the widget back into the grid. Drag-to-reorder
 * within the tray works in customize mode (separate sortable context).
 */
export interface MinimizedPillProps {
  readonly id: string;
  readonly title: string;
  readonly customizing?: boolean;
  readonly onRestore: () => void;
  readonly onClose?: () => void;
  readonly pinned?: boolean;
}

export const MinimizedPill: FC<MinimizedPillProps> = ({
  id,
  title,
  customizing = false,
  onRestore,
  onClose,
  pinned = false,
}) => {
  const draggable = !!customizing && !pinned;
  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({ id, disabled: !draggable });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.4 : undefined,
    zIndex: isDragging ? 50 : undefined,
  };

  const dragProps = draggable ? { ...attributes, ...listeners } : {};

  return (
    <div
      ref={setNodeRef}
      style={style}
      data-widget-id={id}
      {...dragProps}
      className={[
        "inline-flex items-center gap-1.5 rounded-full border bg-bg-card px-3 py-1 text-xs text-text-secondary select-none",
        customizing && !pinned
          ? "cursor-grab border-border-bright active:cursor-grabbing"
          : "border-border",
        pinned ? "border-accent/40" : "",
      ].join(" ")}
    >
      {pinned && (
        <span aria-hidden="true" className="text-accent" title="Pinned">📌</span>
      )}
      <span className="font-medium">{title}</span>
      <div
        className="flex items-center gap-0.5"
        onPointerDown={(e) => e.stopPropagation()}
      >
        <button
          type="button"
          onClick={onRestore}
          aria-label={`Restore ${title}`}
          title="Restore to grid"
          className="rounded-full p-0.5 text-text-dim transition-colors hover:bg-accent-soft hover:text-accent"
        >
          <span aria-hidden="true">▴</span>
        </button>
        {customizing && !pinned && onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label={`Hide ${title}`}
            title="Hide widget"
            className="rounded-full p-0.5 text-text-dim transition-colors hover:bg-critical/10 hover:text-critical"
          >
            ✕
          </button>
        )}
      </div>
    </div>
  );
};

export default WidgetCard;
