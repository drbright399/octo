"""US postal address normalization for the location proposals — made-up
addresses only (Example streets, fictional towns)."""
from __future__ import annotations

import pytest

from apps.octo.proposals import address as a


@pytest.mark.parametrize("given, want", [
    ("Texas", "TX"), ("texas", "TX"), ("TX", "TX"), ("tx", "TX"), (" New  York ", "NY"),
    ("D.C.", "DC"), ("District of Columbia", "DC"), ("Puerto Rico", "PR"),
    ("Tex", "TEX"),                                  # unknown: kept, never guessed
    ("", ""), (None, ""), (42, ""),
])
def test_state_codes(given, want):
    assert a.state_code(given) == want


@pytest.mark.parametrize("given, want", [
    ("00001", "00001"), ("00001-1234", "00001"), ("000011234", "00001"), (" 00501 ", "00501"),
    ("", ""), (None, ""), ("ABC", ""),
])
def test_zip5(given, want):
    assert a.zip5(given) == want


@pytest.mark.parametrize("line1, line2, street, unit, extra", [
    ("700 Example Ln. Suite 400", "", "700 Example Ln.", "Suite 400", ""),
    ("123 Main St, Ste. 2B", "", "123 Main St", "Ste. 2B", ""),
    ("123 Main St #12", "", "123 Main St", "#12", ""),
    ("55 Example Ave 2nd Floor", "", "55 Example Ave", "2nd Floor", ""),
    ("9 Example Rd Bldg B Suite 4", "", "9 Example Rd", "Bldg B Suite 4", ""),
    ("123 Main St", "Suite 200", "123 Main St", "Suite 200", ""),
    ("123 Main St", "Attn: Accounts", "123 Main St", "", "Attn: Accounts"),
    # A street that merely contains a unit word keeps it.
    ("100 Parking Lot Rd", "", "100 Parking Lot Rd", "", ""),
    ("100 Unit Way", "", "100 Unit Way", "", ""),
    # Only a second line: it is the street.
    ("", "200 Example Blvd", "200 Example Blvd", "", ""),
    # A PO box first and a street second: the street is the street.
    ("PO Box 12", "100 Main St", "100 Main St", "", "PO Box 12"),
    # The suite first and the street second: the street is the street.
    ("Suite 400", "700 Example Ln", "700 Example Ln", "Suite 400", ""),
    ("Ste. 2", "9 Example Rd Bldg B", "9 Example Rd", "Bldg B Ste. 2", ""),
    # Only a unit: no street at all.
    ("Suite 400", "", "", "Suite 400", ""),
    ("#12", "Floor 3", "", "#12 Floor 3", ""),
])
def test_units_are_kept_apart(line1, line2, street, unit, extra):
    got = a.parse(line1, line2, "Exampleton", "IL", "00001", 237)
    assert (got.street, got.unit, got.extra) == (street, unit, extra)


def test_query_never_carries_the_unit_label_does():
    got = a.parse("700 Example Ln. Suite 400", "", "Exampleton", "Texas", "75001-0001", 237)
    assert got.query() == "700 Example Ln., Exampleton, TX 75001"
    assert got.label() == "700 Example Ln. Suite 400, Exampleton, TX 75001"
    assert got.missing() == []


def test_the_comparison_key():
    one = a.parse("300 W 5th St", None, "Exampleton", "IL", "", 237)
    two = a.parse("300 W. 5th Street", None, " exampleton ", "Illinois", "00001", 237)
    assert one.key() == two.key() == "300 W 5TH ST|EXAMPLETON|IL"
    # Two suites of one building: one key (that is a shared address) …
    s1 = a.parse("700 Example Ln Suite 400", "", "Exampleton", "TX", "75001", 237)
    s2 = a.parse("700 Example Lane", "Suite 200", "Exampleton", "TX", "75001", 237)
    assert s1.key() == s2.key()
    # … but different source data (the digest keeps the unit and the ZIP).
    assert s1.digest() != s2.digest()
    # A cosmetic edit is the same data.
    assert one.digest()["street"] == two.digest()["street"]
    assert a.parse("1 North Example Road", "", "X", "OH", "", 237).key() == \
        a.parse("1 N Example Rd.", "", "X", "Ohio", "", 237).key()


def test_a_suite_first_never_becomes_the_street():
    got = a.parse("Suite 400", "700 Example Ln", "Exampleton", "TX", "75001", 237)
    assert got.query() == "700 Example Ln, Exampleton, TX 75001"         # never the suite
    assert got.label() == "700 Example Ln Suite 400, Exampleton, TX 75001"
    # Two unrelated tenants in the same city, a "Suite 400" each, are NOT one
    # address (the street decides).
    other = a.parse("Suite 400", "12 Other Example St", "Exampleton", "TX", "75001", 237)
    assert got.key() != other.key()
    only = a.parse("Suite 400", "", "Exampleton", "TX", "75001", 237)
    assert only.missing() == ["street"] and only.key() == ""


def test_incomplete_and_po_boxes():
    no_zip = a.parse("1 Example Rd", "", "Exampleton", "TX", "", 237)
    assert no_zip.missing() == ["zip"]
    box = a.parse("P.O. Box 77", "", "Exampleton", "TX", "75001", 237)
    assert box.po_box and box.missing() == ["street"] and box.key() == ""
    bare = a.parse("", "", "", "", "", 237)
    assert bare.missing() == ["street", "zip", "city", "state"]


@pytest.mark.parametrize("country, want", [
    (237, "US"), (None, "US"), ("237", "US"), (75, "other"), ("x", "other"), (True, "other"),
])
def test_us_only(country, want):
    assert a.parse("1 Example Rd", "", "Exampleton", "", "", country).country == want


def test_cleaning_and_bounds():
    got = a.parse("1\tExample\x00 Rd", None, "Example\nTown", "IL", "00001", 237)
    assert got.street == "1 Example Rd" and got.city == "Example Town"
    long = a.parse("1 " + "Long " * 60 + "Rd", None, "Town", "IL", "00001", 237)
    assert len(long.street) <= a.MAX_PART and len(long.label()) <= a.MAX_LABEL


def test_name_tokens():
    assert a.name_tokens("Example Pharmacy - Riverton", None, "HQ #2") == \
        {"example", "pharmacy", "riverton", "hq", "2"}
