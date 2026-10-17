"""apps/octo/branding.py — palette allow-list + the legacy palette alias.

Exercises the real `get_branding()` resolver; only the process
environment is varied (monkeypatch), nothing is stubbed.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from apps.octo import branding

# The key the gold palette shipped under before it was renamed. Live
# deployments may still carry it in ATHENA_BUNDLE_BRAND_PALETTE, so the
# regression test needs the literal — this constant is the only place it
# appears in the backend tests.
LEGACY_GOLD_KEY = "micro-it"

_BRAND_ENV = (
    "ATHENA_BUNDLE_BRAND_NAME",
    "ATHENA_BUNDLE_BRAND_PALETTE",
    "ATHENA_BUNDLE_BRAND_LOGO_URL",
    "ATHENA_BUNDLE_BRAND_CONTACT_EMAIL",
    "ATHENA_BUNDLE_BRAND_PDF_HEADER_IMAGE",
    "ATHENA_BUNDLE_BRAND_PDF_FOOTER_TEXT",
)


@pytest.fixture(autouse=True)
def _clean_brand_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _BRAND_ENV:
        monkeypatch.delenv(name, raising=False)


def test_defaults_when_nothing_is_configured() -> None:
    b = branding.get_branding()
    assert (b.accent_palette, b.accent_hex) == ("violet", "#a78bfa")
    assert b.name == "Athena"


def test_midas_palette_is_the_gold_accent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATHENA_BUNDLE_BRAND_PALETTE", "midas")
    b = branding.get_branding()
    assert (b.accent_palette, b.accent_hex) == ("midas", "#FFC600")


def test_legacy_palette_key_still_resolves_to_gold(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deployment configured before the rename keeps its accent, and the
    branding it reports (PDF exports, the search.export audit row) carries
    the CANONICAL key — the old one is never emitted."""
    monkeypatch.setenv("ATHENA_BUNDLE_BRAND_PALETTE", LEGACY_GOLD_KEY)
    monkeypatch.setenv("ATHENA_BUNDLE_BRAND_NAME", "Example MSP")
    b = branding.get_branding()
    assert (b.accent_palette, b.accent_hex) == ("midas", "#FFC600")
    assert b.name == "Example MSP"


def test_legacy_key_is_an_alias_not_a_palette() -> None:
    assert LEGACY_GOLD_KEY not in branding.PALETTE_ACCENTS
    assert branding.resolve_palette(LEGACY_GOLD_KEY) == "midas"
    # Every alias must land on a real palette.
    for target in branding._LEGACY_PALETTE_ALIASES.values():
        assert target in branding.PALETTE_ACCENTS


@pytest.mark.parametrize(
    "junk",
    ["#FFC600", "gold", "MIDAS", " midas", "", "violet; color:red", "__class__"],
)
def test_unknown_palette_names_fall_back_to_default(
    monkeypatch: pytest.MonkeyPatch, junk: str
) -> None:
    """Names only, exact match — never a hex code or a near-miss."""
    monkeypatch.setenv("ATHENA_BUNDLE_BRAND_PALETTE", junk)
    monkeypatch.setenv("ATHENA_BUNDLE_BRAND_NAME", "Example MSP")
    b = branding.get_branding()
    assert (b.accent_palette, b.accent_hex) == ("violet", "#a78bfa")


def test_palette_keys_match_the_frontend_enum() -> None:
    """Adding a palette is a three-file edit (branding.py, index.css,
    lib/appearance.ts). Catch a rename that misses the backend."""
    src = (
        Path(__file__).resolve().parents[2]
        / "athena" / "web" / "src" / "lib" / "appearance.ts"
    ).read_text(encoding="utf-8")
    m = re.search(r"export const BUNDLE_IDS = \[([^\]]+)\] as const;", src)
    assert m, "BUNDLE_IDS not found in lib/appearance.ts"
    frontend = set(re.findall(r'"([^"]+)"', m.group(1)))
    assert frontend == set(branding.PALETTE_ACCENTS)
