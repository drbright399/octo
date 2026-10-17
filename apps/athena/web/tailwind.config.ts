import type { Config } from "tailwindcss";

/**
 * Theme tokens mirror `~/octo-dashboard/public/css/style.css` 1:1 so the
 * new framework-rendered console reads as a continuation of the existing
 * OCTO dashboard, not a rebrand. Token values come from the dark + light
 * palettes there.
 *
 * Components reference tokens via Tailwind utilities like `bg-bg-deep`,
 * `text-text-primary`, `ring-border`. The runtime values come from CSS
 * variables defined in `src/index.css`, so the dark/light theme toggle
 * just flips `data-theme` on `<html>` without re-rendering React.
 */

const config: Config = {
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx}",
    "../widgets/components/**/*.tsx",
  ],
  theme: {
    extend: {
      colors: {
        "bg-deep": "var(--bg-deep)",
        "bg-surface": "var(--bg-surface)",
        "bg-card": "var(--bg-card)",
        "bg-card-hover": "var(--bg-card-hover)",
        "bg-elevated": "var(--bg-elevated)",
        "bg-input": "var(--bg-input)",
        border: "var(--border)",
        "border-bright": "var(--border-bright)",
        "text-primary": "var(--text-primary)",
        "text-secondary": "var(--text-secondary)",
        "text-dim": "var(--text-dim)",
        accent: "var(--accent)",
        "accent-strong": "var(--accent-strong)",
        "accent-cta": "var(--accent-cta)",
        "accent-soft": "var(--accent-soft)",
        "accent-glow": "var(--accent-glow)",
        "text-on-accent": "var(--text-on-accent)",
        critical: "var(--critical)",
        high: "var(--high)",
        medium: "var(--medium)",
        low: "var(--low)",
        info: "var(--info)",
        success: "var(--success)",
      },
      fontFamily: {
        // Resolve via CSS vars so the Theme v2 Appearance panel's
        // data-font="..." can swap the family at runtime without rebuild.
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
      borderRadius: {
        // Same pattern — data-corners="terminal|default|friendly" maps to
        // these via --r-sm / --r-md / --r-lg in index.css.
        sm: "var(--r-sm)",
        DEFAULT: "var(--r-md)",
        md: "var(--r-md)",
        lg: "var(--r-lg)",
      },
      animation: {
        pulse: "pulse 2s infinite",
        "pulse-fast": "pulse 1.6s infinite",
        "pulse-rapid": "pulse 0.4s infinite",
      },
      keyframes: {
        pulse: {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.5", transform: "scale(1.4)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
