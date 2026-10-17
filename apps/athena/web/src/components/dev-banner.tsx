import type { FC } from "react";

/**
 * Top-strip medium shown ONLY when running against Vite's dev server
 * (i.e. ./scripts/dev.sh against the local synthetic data root).
 *
 * Detection: `import.meta.env.MODE === "development"`. Vite sets this
 * at build time — a production `vite build` produces MODE="production"
 * and this component returns null. Physically impossible to ship the
 * banner to a live container.
 *
 * Terminal-style bracket framing (the console's visual language)
 * rather than a bubbly toast.
 */
const DevBanner: FC = () => {
  if (import.meta.env.MODE !== "development") return null;
  return (
    <div
      role="alert"
      aria-live="polite"
      className="relative z-10 border-b border-medium/40 bg-medium/10 px-4 py-1.5 font-mono text-[11px] uppercase tracking-wider text-medium"
    >
      <div className="mx-auto flex max-w-[1500px] items-center justify-center gap-2">
        <span aria-hidden="true">[</span>
        <span>DEV · synthetic data only · not for customer demo</span>
        <span aria-hidden="true">]</span>
      </div>
    </div>
  );
};

export default DevBanner;
