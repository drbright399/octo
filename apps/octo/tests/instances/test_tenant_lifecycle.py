"""Tenant lifecycle vocabulary + name normalisation (pure helpers)."""
from __future__ import annotations

import pytest

from apps.octo import client_provisioning
from apps.octo.instances import tenant_lifecycle as tl


def test_enums_match_the_provisioning_vocabulary_and_the_migration():
    """One vocabulary: the CHECK lists in migration 033, the provisioning
    constants and what the API offers must never drift apart."""
    from apps.octo.migration import list_migrations

    sql = next(m for m in list_migrations() if m.number == 33).sql
    for value in tl.ORIGINS + tl.KINDS + tl.REVIEW_STATES + tl.AI_POLICIES:
        assert f"'{value}'" in sql, value
    assert tl.KINDS == client_provisioning.KINDS
    assert tl.AI_POLICIES == client_provisioning.AI_POLICIES
    assert "ignored" not in tl.KINDS               # ruling: nothing is "ignored"
    assert "none" in tl.COMPLIANCE_TAGS and "hipaa" in tl.COMPLIANCE_TAGS


@pytest.mark.parametrize("a, b", [
    ("Acme Corp", "ACME, Inc."),
    ("Acme Corp.", "acme"),
    ("Widget Co LLC", "Widget Co"),
    ("  Widget   Co  ", "widget co"),
    ("Café Médical", "cafe medical"),
    ("Smith & Sons Ltd", "Smith and Sons"),
    ("Acme Company", "acme corporation"),
])
def test_normalise_name_treats_obvious_variants_as_one_name(a, b):
    assert tl.normalise_name(a) == tl.normalise_name(b)


@pytest.mark.parametrize("a, b", [
    ("Acme Corp", "Acme Corp 2"),
    ("Acme North", "Acme South"),
    ("Acme", "Acme Dental"),
])
def test_normalise_name_keeps_distinct_names_distinct(a, b):
    assert tl.normalise_name(a) != tl.normalise_name(b)


def test_normalise_name_is_defensive_about_vendor_input():
    assert tl.normalise_name(None) == ""
    assert tl.normalise_name(42) == ""
    assert tl.normalise_name("\x00\x1f  ") == ""
    assert tl.normalise_name("Inc") == "inc"          # a lone suffix stays a name
    assert len(tl.normalise_name("x" * 100_000)) <= tl.MAX_DISPLAY_NAME * 2


@pytest.mark.parametrize("name, slug", [
    ("Acme Corp", "acme-corp"),
    ("ACME, Inc.", "acme-inc"),
    ("  Widget -- Co  ", "widget-co"),
    ("Café Médical", "cafe-medical"),
    ("---", "site"),
    ("Ωμέγα", "site"),
    (None, "site"),
])
def test_slug_from_name(name, slug):
    out = tl.slug_from_name(name)
    assert out == slug
    assert client_provisioning._SLUG_RE.match(out)


def test_slug_from_name_is_bounded():
    out = tl.slug_from_name("a" * 500)
    assert len(out) <= tl.MAX_SLUG_CHARS and client_provisioning._SLUG_RE.match(out)


def test_clean_display_name_flattens_and_bounds():
    assert tl.clean_display_name("Acme\nCorp\t\x07 Site") == "Acme Corp Site"
    assert len(tl.clean_display_name("y" * 1000)) <= tl.MAX_DISPLAY_NAME
    assert tl.clean_display_name(None) == ""


def test_compliance_flags_validation():
    assert tl.validate_compliance_flags(["pci", "hipaa", "hipaa"]) == ["hipaa", "pci"]
    assert tl.validate_compliance_flags([]) == []
    with pytest.raises(ValueError):
        tl.validate_compliance_flags(["gdpr"])            # not in the curated set
    with pytest.raises(ValueError):
        tl.validate_compliance_flags(["none", "hipaa"])   # 'none' is exclusive
    with pytest.raises(ValueError):
        tl.validate_compliance_flags([1])
    assert tl.parse_compliance_flags('["hipaa","bogus"]') == ["hipaa"]
    assert tl.parse_compliance_flags("not json") == []
    assert tl.parse_compliance_flags(None) == []
    assert tl.compliance_flags_json(["pci", "hipaa"]) == '["hipaa","pci"]'


# ---------------------------------------------------------------------------
# Duplicate hints (a chip in the tenant manager — never an automatic merge)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a, b, rule", [
    # The shorter name, legal suffix stripped, is the leading part of the longer.
    ("Acme Holdings Tax", "Acme Holdings LLC", "name-prefix"),
    ("Acme Holdings LLC", "Acme Holdings Tax", "name-prefix"),
    ("Widget Works Dental Care", "Widget Works, LLC", "name-prefix"),
    # The same business after normalisation.
    ("Acme Corp", "ACME, Inc.", "same-name"),
    ("Widget Co", "Widget Company", "same-name"),
    ("Smith & Jones, P.L.L.C.", "Smith and Jones", "same-name"),   # dotted initials
    ("Smith & Jones, P.A.", "Smith and Jones", "same-name"),       # professional assoc.
    ("The Acme Holdings", "Acme Holdings LLC", "same-name"),       # leading "the"
])
def test_duplicate_hint_pairs_likely_duplicates(a, b, rule):
    assert tl.duplicate_rule(tl.duplicate_hint_key(a), tl.duplicate_hint_key(b)) == rule


@pytest.mark.parametrize("a, b", [
    # Sharing a first word is not enough.
    ("Acme Holdings Tax", "Acme Dental"),
    ("Globex Dental", "Globex Legal"),
    # Sharing two leading words is not enough either: siblings, not duplicates.
    ("Acme Holdings Tax", "Acme Holdings Payroll"),
    ("First National Bank", "First National Insurance"),
    # A lone word is too generic to be the "leading part" of anything.
    ("Acme", "Acme Dental"),
    ("Globex", "Globex Group"),
    # "Group" is part of a name, never a suffix to strip.
    ("Acme Group", "Acme"),
    # Numbers distinguish.
    ("Acme Corp", "Acme Corp 2"),
])
def test_duplicate_hint_does_not_pair_unrelated_tenants(a, b):
    assert tl.duplicate_rule(tl.duplicate_hint_key(a), tl.duplicate_hint_key(b)) is None


def test_duplicate_hints_are_symmetric_bounded_and_defensive():
    hints = tl.duplicate_hints([
        ("acme-holdings-llc", "Acme Holdings LLC"),
        ("acme-holdings-tax", "Acme Holdings Tax"),
        ("acme-dental", "Acme Dental"),
        ("globex-corp", "Globex Corp"),
        ("globex-inc", "Globex, Inc."),
        ("blank", "---"),
    ])
    assert hints == {
        "acme-holdings-llc": [("acme-holdings-tax", "name-prefix")],
        "acme-holdings-tax": [("acme-holdings-llc", "name-prefix")],
        "globex-corp": [("globex-inc", "same-name")],
        "globex-inc": [("globex-corp", "same-name")],
    }
    many = tl.duplicate_hints([(f"acme-{n}", "Acme Corp") for n in range(20)])
    assert all(len(v) == tl.DUPLICATE_HINTS_PER_TENANT for v in many.values())
    assert tl.duplicate_hint_key(None) == () and tl.duplicate_hint_key("---") == ()
    assert tl.duplicate_rule((), ("acme",)) is None
