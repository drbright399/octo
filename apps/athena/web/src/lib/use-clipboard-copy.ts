/**
 * useClipboardCopy — copy-to-clipboard that tells the truth.
 *
 * `navigator.clipboard` is undefined outside a secure context (plain-HTTP or
 * LAN-IP console, some embedded browsers) and `writeText` can reject
 * (permission denied, document not focused). A button that flips to "copied"
 * regardless is harmless for a URL and dangerous for a value that can never be
 * shown again — so the state only becomes "copied" once the write RESOLVES,
 * and every other outcome is "failed".
 *
 * The value passes straight through to the clipboard API: never stored,
 * never logged.
 */
import { useCallback, useEffect, useRef, useState } from "react";

export type CopyState = "idle" | "copied" | "failed";

const COPIED_FLASH_MS = 1400;

export function useClipboardCopy(
  onFailed?: () => void,
): { readonly state: CopyState; readonly copy: (value: string) => Promise<void> } {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<number | null>(null);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      if (timer.current !== null) window.clearTimeout(timer.current);
    };
  }, []);

  const copy = useCallback(
    async (value: string): Promise<void> => {
      if (timer.current !== null) window.clearTimeout(timer.current);
      let ok = false;
      try {
        const clipboard = navigator.clipboard as Clipboard | undefined;
        if (clipboard && typeof clipboard.writeText === "function") {
          await clipboard.writeText(value);
          ok = true;
        }
      } catch {
        ok = false;
      }
      if (!alive.current) return;
      if (ok) {
        setState("copied");
        timer.current = window.setTimeout(() => setState("idle"), COPIED_FLASH_MS);
      } else {
        // Sticky: a failure must not quietly fade back to "copy".
        setState("failed");
        onFailed?.();
      }
    },
    [onFailed],
  );

  return { state, copy };
}
