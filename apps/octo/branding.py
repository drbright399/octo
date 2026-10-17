"""MSP branding source for audit-grade exports + future MSP white-label.

Surfaces a single `get_branding()` call that returns the bundle's
identity (name, accent color, logo URL, contact email). Used by:
  - apps/octo/api/routers/search_export.py — branded PDF reports
  - (future) apps/octo/api/routers/email_sender.py — branded email
  - (future) apps/octo/api/routers/admin_system.py — super_admin
    System panel reads + writes the same source

**Resolution order** (first hit wins):
  1. Bundle config DB (future, Task #10) — `bundle_config.branding`
     row in registry.db. NOT yet wired; returns None when missing.
  2. Environment variables: `ATHENA_BUNDLE_BRAND_*`
  3. Athena defaults — violet, "Athena", no logo

**Why this layer:** Audit exports + future MSP-facing surfaces all
need a consistent branding source. Threading config refs through every
caller is fragile; one resolver lets us swap env → DB → cache as the
deployment surface matures without touching every export call site.

**What we deliberately DON'T do:**
- Free-form hex input — accent must be one of the 7 curated palette
  names. The hex value
  is derived from the name via a hardcoded map.
- Image upload here. Logo is a URL the bundle points at (e.g.,
  https://msp.example.test/logo.svg). Image hosting belongs in the bundle's
  own static asset path or an MSP-owned CDN, not OCTO storage.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


# Same 7 palette accents as the frontend's data-bundle attribute set.
# Keep this in sync with `apps/athena/web/src/index.css` and
# `apps/athena/web/src/pages/settings/appearance.tsx`. Adding a palette
# is a three-file edit by design — there's no runtime upload path.
PALETTE_ACCENTS: dict[str, str] = {
    "violet":   "#a78bfa",
    "midas":    "#FFC600",
    "indigo":   "#818cf8",
    "cyan":     "#22d3ee",
    "sky":      "#38bdf8",
    "rose":     "#fb7185",
    "emerald":  "#34d399",
}

# LEGACY ALIAS — the gold palette was originally keyed by a company brand
# name. Deployments that still carry the old key in
# ATHENA_BUNDLE_BRAND_PALETTE keep their gold accent: the value is mapped
# to the current key where it is read (`resolve_palette`). This map is the
# ONLY place the old key may appear in the backend; it is never emitted
# (exports report the canonical key). Frontend twin:
# `LEGACY_BUNDLE_ALIASES` in apps/athena/web/src/lib/appearance.ts.
_LEGACY_PALETTE_ALIASES: dict[str, str] = {
    "micro-it": "midas",
}

DEFAULT_PALETTE = "violet"
DEFAULT_NAME = "Athena"
DEFAULT_CONTACT_EMAIL = "noreply@athena.local"


@dataclass(frozen=True)
class Branding:
    """Bundle identity used by exports + branded surfaces."""

    name: str
    """MSP display name (e.g., 'Example MSP' or 'Athena' for unbranded)."""
    accent_hex: str
    """The hex color resolved from the bundle's chosen palette name.
    Used ONLY for accent elements (rule lines, small badges, table
    header bars) — NEVER for body text. Some palettes (e.g., the midas
    gold) have poor contrast against white paper; body text always
    renders in black so the report stays readable when printed."""
    accent_palette: str
    """The palette key — one of PALETTE_ACCENTS. Stored alongside hex so
    future server-side rendering can pick matching secondary tones."""
    logo_url: str | None
    """Optional fully-qualified URL the MSP points at. None = no logo,
    fall back to a text-only header in the PDF."""
    contact_email: str
    """Address that appears in the report footer + any operator-facing
    'questions about this export?' affordance."""
    pdf_header_image_path: str | None
    """Optional path to a local PNG/JPG (e.g., a corporate letterhead
    banner). When set, rendered at the top of the PDF's first page
    instead of the text-only branded header. Resolution: bundle-local
    filesystem path, NOT a URL — keeps exports offline + auditable."""
    pdf_footer_text: str | None
    """Optional custom footer text. Replaces the default
    `{name} · audit export · contact {contact_email}` line. Use for
    legal disclaimers, document classification markings ("CONFIDENTIAL
    — FOR INTERNAL USE"), or corporate compliance footers."""


def resolve_palette(raw: str | None) -> str:
    """Map a configured palette name onto a PALETTE_ACCENTS key.

    Legacy aliases are mapped first; anything not on the allow-list
    (unknown name, hex code, empty) falls back to DEFAULT_PALETTE.
    Exact-match only — same strictness as the frontend enum.
    """
    if raw is None:
        return DEFAULT_PALETTE
    key = _LEGACY_PALETTE_ALIASES.get(raw, raw)
    return key if key in PALETTE_ACCENTS else DEFAULT_PALETTE


def _from_env() -> Branding | None:
    """Parse branding from ATHENA_BUNDLE_BRAND_* env vars. Returns None
    when no overrides are set (caller falls back to defaults)."""
    name = os.environ.get("ATHENA_BUNDLE_BRAND_NAME")
    palette = os.environ.get("ATHENA_BUNDLE_BRAND_PALETTE")
    logo = os.environ.get("ATHENA_BUNDLE_BRAND_LOGO_URL")
    contact = os.environ.get("ATHENA_BUNDLE_BRAND_CONTACT_EMAIL")
    pdf_header = os.environ.get("ATHENA_BUNDLE_BRAND_PDF_HEADER_IMAGE")
    pdf_footer = os.environ.get("ATHENA_BUNDLE_BRAND_PDF_FOOTER_TEXT")
    if not any([name, palette, logo, contact, pdf_header, pdf_footer]):
        return None
    # Validate palette against the allow-list. Unknown name → default.
    # NEVER trust an env value to be a valid hex code directly — only
    # palette NAMES are accepted (a curated palette only). Legacy names are
    # alias-mapped inside resolve_palette.
    palette_key = resolve_palette(palette)
    return Branding(
        name=name or DEFAULT_NAME,
        accent_hex=PALETTE_ACCENTS[palette_key],
        accent_palette=palette_key,
        logo_url=logo or None,
        contact_email=contact or DEFAULT_CONTACT_EMAIL,
        pdf_header_image_path=pdf_header or None,
        pdf_footer_text=pdf_footer or None,
    )


def get_branding() -> Branding:
    """Return the active bundle branding.

    Future: read from registry.db's `bundle_config` table first
    (Task #10). For now: env vars → Athena defaults.
    """
    # TODO when Task #10 lands: query bundle_config.branding row here
    # and return Branding(...) from that. Env still wins as a deploy
    # override for split-brain testing.
    env = _from_env()
    if env is not None:
        return env
    return Branding(
        name=DEFAULT_NAME,
        accent_hex=PALETTE_ACCENTS[DEFAULT_PALETTE],
        accent_palette=DEFAULT_PALETTE,
        logo_url=None,
        contact_email=DEFAULT_CONTACT_EMAIL,
        pdf_header_image_path=None,
        pdf_footer_text=None,
    )
