/**
 * useClickOutsideClose — close a panel/drawer/window when the user
 * clicks anywhere outside its DOM subtree, with a "are you sure?"
 * confirm step when there are unsaved edits.
 *
 * Why a custom hook (not a backdrop overlay): floating ticket windows
 * and side drawers are NOT modal — the operator should still be able
 * to scroll the list behind, click row buttons, etc. A full-screen
 * backdrop would block that. A document-level listener gives us
 * click-outside semantics without disabling the rest of the page.
 *
 * Implementation note: we track mousedown + mouseup separately. A
 * "click outside" only counts when BOTH the press AND the release
 * happened outside the watched element. This prevents two
 * fail-modes:
 *
 *   1. Drag-selecting text that starts inside but ends outside —
 *      the panel would close mid-selection.
 *   2. Native <select> dropdowns rendered as OS-level popups (outside
 *      the React tree) — their mouseup events would otherwise look
 *      like outside-clicks.
 *
 * The hook calls `isDirty()` lazily right before closing so the
 * consumer can keep `isDirty` cheap (just a flag check). When dirty,
 * `window.confirm` blocks the thread and the operator gets a native
 * dialog. We can swap this for a custom-styled modal later if the
 * native prompt feels too jarring; the contract is the same.
 */
import { useEffect, useRef } from "react";

export function useClickOutsideClose<T extends HTMLElement>(
  ref: React.RefObject<T | null>,
  isDirty: () => boolean,
  onClose: () => void,
): void {
  const mouseDownInside = useRef(false);
  // Stash the latest callbacks in refs so we don't have to re-bind the
  // document listeners on every render.
  const isDirtyRef = useRef(isDirty);
  const onCloseRef = useRef(onClose);
  isDirtyRef.current = isDirty;
  onCloseRef.current = onClose;

  useEffect(() => {
    const onMouseDown = (e: MouseEvent): void => {
      const target = e.target as Node | null;
      mouseDownInside.current = !!(ref.current && target && ref.current.contains(target));
    };

    const onMouseUp = (e: MouseEvent): void => {
      // Drag that started inside — never treat as outside click,
      // regardless of where it ended.
      if (mouseDownInside.current) {
        mouseDownInside.current = false;
        return;
      }
      const target = e.target as Node | null;
      if (ref.current && target && ref.current.contains(target)) {
        return;
      }
      // Opt-out: if the click landed on an element (or any ancestor)
      // marked `data-keeps-window-open`, this isn't really an "outside
      // click that means close" — it's a click on a SIBLING surface
      // that's about to open a different ticket. Without this guard,
      // both setState calls (open-new + close-old) batch in the same
      // event tick and the close wins, so the new window appears for
      // one frame and vanishes. The opt-out marker is applied to:
      //   - agent triage feed buttons
      //   - main /tickets table rows
      //   - recently-edited + newly-arrived strip cards
      if (target instanceof Element) {
        if (target.closest("[data-keeps-window-open]")) return;
      }
      // Confirm before closing if dirty.
      if (isDirtyRef.current()) {
        const ok = window.confirm(
          "You have unsaved changes. Discard them and close?",
        );
        if (!ok) return;
      }
      onCloseRef.current();
    };

    document.addEventListener("mousedown", onMouseDown);
    document.addEventListener("mouseup", onMouseUp);
    return () => {
      document.removeEventListener("mousedown", onMouseDown);
      document.removeEventListener("mouseup", onMouseUp);
    };
  }, [ref]);
}
