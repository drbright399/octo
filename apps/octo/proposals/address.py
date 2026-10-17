"""US postal addresses as an integration hands them over (Autotask's
address1 / address2 / city / state / postalCode / countryID) — cleaned, made
comparable, split for the geocoder.

What it does:
  * whitespace and non-printable characters cleaned; every part bounded;
  * the STATE as its USPS abbreviation ("Texas", "texas", "TX" → "TX");
    an unknown value is kept (upper-case) and never guessed;
  * the ZIP as five digits ("00001-1234" → "00001"; empty stays empty);
  * a SUITE / UNIT ("Suite 400", "Ste. 2", "#12", "2nd Floor") taken off the
    street — from the end of address1 or as all of address2 — and kept for
    the LABEL; the geocoder's query never carries it (the Census geocoder
    matches streets, and a unit only makes it miss);
  * a PO box is not a street (`po_box`; "incomplete");
  * US only: countryID 237 (or none given) is the US; anything else is
    `country == "other"` and the caller skips it.

`key` compares two addresses: upper-case, punctuation dropped, the common
street suffixes and directionals abbreviated ("300 W. 5th Street" and
"300 W 5th St" are the same key), the unit and the ZIP left out (two
businesses in one building share a key — that is the point of the
`shared_address` warning). `digest` is what the source hash is taken over:
the key's parts plus the unit and the ZIP, so a cosmetic edit in the source
("St" → "Street") does not re-propose.

Nothing here is logged: an address is client data.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

US_COUNTRY_ID = 237
MAX_PART = 128
MAX_LABEL = 120

STATES: dict[str, str] = {
    "ALABAMA": "AL", "ALASKA": "AK", "ARIZONA": "AZ", "ARKANSAS": "AR", "CALIFORNIA": "CA",
    "COLORADO": "CO", "CONNECTICUT": "CT", "DELAWARE": "DE", "FLORIDA": "FL",
    "GEORGIA": "GA", "HAWAII": "HI", "IDAHO": "ID", "ILLINOIS": "IL", "INDIANA": "IN",
    "IOWA": "IA", "KANSAS": "KS", "KENTUCKY": "KY", "LOUISIANA": "LA", "MAINE": "ME",
    "MARYLAND": "MD", "MASSACHUSETTS": "MA", "MICHIGAN": "MI", "MINNESOTA": "MN",
    "MISSISSIPPI": "MS", "MISSOURI": "MO", "MONTANA": "MT", "NEBRASKA": "NE", "NEVADA": "NV",
    "NEW HAMPSHIRE": "NH", "NEW JERSEY": "NJ", "NEW MEXICO": "NM", "NEW YORK": "NY",
    "NORTH CAROLINA": "NC", "NORTH DAKOTA": "ND", "OHIO": "OH", "OKLAHOMA": "OK",
    "OREGON": "OR", "PENNSYLVANIA": "PA", "RHODE ISLAND": "RI", "SOUTH CAROLINA": "SC",
    "SOUTH DAKOTA": "SD", "TENNESSEE": "TN", "TEXAS": "TX", "UTAH": "UT", "VERMONT": "VT",
    "VIRGINIA": "VA", "WASHINGTON": "WA", "WEST VIRGINIA": "WV", "WISCONSIN": "WI",
    "WYOMING": "WY", "DISTRICT OF COLUMBIA": "DC", "WASHINGTON DC": "DC",
    "WASHINGTON D C": "DC", "D C": "DC", "PUERTO RICO": "PR", "GUAM": "GU",
    "US VIRGIN ISLANDS": "VI", "VIRGIN ISLANDS": "VI", "AMERICAN SAMOA": "AS",
    "NORTHERN MARIANA ISLANDS": "MP",
}
ABBREVIATIONS = frozenset(STATES.values())

# Comparison only (`key`): USPS street suffixes and directionals.
_WORDS: dict[str, str] = {
    "STREET": "ST", "AVENUE": "AVE", "AV": "AVE", "ROAD": "RD", "DRIVE": "DR", "LANE": "LN",
    "BOULEVARD": "BLVD", "COURT": "CT", "PLACE": "PL", "HIGHWAY": "HWY", "PARKWAY": "PKWY",
    "CIRCLE": "CIR", "TERRACE": "TER", "TRAIL": "TRL", "SQUARE": "SQ", "EXPRESSWAY": "EXPY",
    "FREEWAY": "FWY", "CENTER": "CTR", "PIKE": "PIKE", "ROUTE": "RTE", "WAY": "WAY",
    "NORTH": "N", "SOUTH": "S", "EAST": "E", "WEST": "W", "NORTHEAST": "NE",
    "NORTHWEST": "NW", "SOUTHEAST": "SE", "SOUTHWEST": "SW",
    "SUITE": "STE", "APARTMENT": "APT", "BUILDING": "BLDG", "FLOOR": "FL", "ROOM": "RM",
}

_UNIT_WORDS = r"SUITE|STE|UNIT|APT|APARTMENT|BLDG|BUILDING|FLOOR|FLR|FL|RM|ROOM|DEPT|SPC|SPACE|LOT|PMB"
# The unit's own id: starts with a digit ("400", "2B", "4-A"), or is ONE
# letter (+ digits) ("B", "C2") — so "… Parking Lot Rd" keeps its "Lot Rd".
_UNIT_ID = r"(?:\d[A-Z0-9-]*|[A-Z](?:-?\d+)?)"
_UNIT = (r"(?:(?:" + _UNIT_WORDS + r")\.?\s*#?\s*|#\s*)" + _UNIT_ID + r"\b"
         r"|\d+(?:ST|ND|RD|TH)\s+(?:FLOOR|FLR|FL)\b\.?")
# A unit at the END of a street line: ", Suite 400" / " Ste. 2B" / " #12" /
# " 2nd Floor". Taken off repeatedly ("… Bldg B Suite 4").
_TRAILING_UNIT = re.compile(r"(?:\s*,\s*|\s+)(?P<unit>" + _UNIT + r")\s*$", re.IGNORECASE)
# All of a line is a unit ("Suite 400", "#12", "3rd floor").
_WHOLE_UNIT = re.compile(r"^\s*(?:" + _UNIT + r")\s*$", re.IGNORECASE)
_PO_BOX = re.compile(r"^\s*(?:P\.?\s*O\.?\s*|POST\s+OFFICE\s+)BOX\b", re.IGNORECASE)
_ZIP = re.compile(r"\b(\d{5})(?:-?\d{4})?\b")


def clean(value: Any, limit: int = MAX_PART) -> str:
    """One line, printable, collapsed whitespace, bounded; '' for a non-string."""
    if not isinstance(value, str):
        return ""
    flat = " ".join("".join(c if c.isprintable() else " " for c in value).split())
    return flat[:limit].strip()


def state_code(value: Any) -> str:
    """The USPS abbreviation for a US state / territory name or code; an
    unknown value upper-cased as given (never guessed); '' for none."""
    text = " ".join(clean(value, 40).upper().replace(".", " ").split())
    if not text or text in ABBREVIATIONS:
        return text
    return STATES.get(text, text)


def zip5(value: Any) -> str:
    m = _ZIP.search(clean(value, 20))
    return m.group(1) if m else ""


def split_unit(street: str) -> tuple[str, str]:
    """(street without its trailing unit(s), the unit text as given)."""
    units: list[str] = []
    rest = street
    for _ in range(3):
        m = _TRAILING_UNIT.search(rest)
        if not m or m.start() == 0:
            break
        units.insert(0, m.group("unit").strip())
        rest = rest[:m.start()].rstrip(" ,")
    return rest, " ".join(units)


def _key_words(text: str) -> str:
    words = re.sub(r"[^A-Z0-9 ]", " ", text.upper().replace("#", " ")).split()
    return " ".join(_WORDS.get(w, w) for w in words)


@dataclass(frozen=True)
class Address:
    street: str          # as given (cleaned), the unit taken off
    unit: str            # "Suite 400" — the label keeps it, the query never
    extra: str           # an address2 that is neither a unit nor a street
    city: str
    state: str           # USPS abbreviation when known
    zip: str             # five digits, or ''
    country: str         # 'US' | 'other'
    po_box: bool = False

    @property
    def us(self) -> bool:
        return self.country == "US"

    def missing(self) -> list[str]:
        """What a usable US street address lacks: 'street' (none, or only a
        PO box), 'zip', 'city' / 'state' (when there is no ZIP either)."""
        out: list[str] = []
        if not self.street or self.po_box:
            out.append("street")
        if not self.zip:
            out.append("zip")
            if not self.city:
                out.append("city")
            if not self.state:
                out.append("state")
        return out

    def key(self) -> str:
        """Comparison key: street (no unit) + city + state — '' when there is
        no street to compare."""
        if not self.street or self.po_box:
            return ""
        return "|".join((_key_words(self.street), _key_words(self.city), self.state))

    def digest(self) -> dict[str, str]:
        """What the source hash is taken over (normalized; cosmetic edits do
        not change it)."""
        return {"street": _key_words(self.street), "unit": _key_words(self.unit),
                "city": _key_words(self.city), "state": self.state, "zip": self.zip,
                "country": self.country, "po_box": "1" if self.po_box else ""}

    def query(self) -> str:
        """The geocoder's one line: street, city, ST ZIP — never the unit,
        never anything else."""
        tail = " ".join(p for p in (self.state, self.zip) if p)
        return ", ".join(p for p in (self.street, self.city, tail) if p)

    def label(self) -> str:
        """The pin's label as people read it: street + unit, city, ST ZIP."""
        street = " ".join(p for p in (self.street, self.unit) if p)
        tail = " ".join(p for p in (self.state, self.zip) if p)
        return ", ".join(p for p in (street, self.city, tail) if p)[:MAX_LABEL].strip(" ,")

    def as_dict(self) -> dict[str, Any]:
        return {"street": self.street, "unit": self.unit, "extra": self.extra,
                "city": self.city, "state": self.state, "zip": self.zip,
                "country": self.country, "po_box": self.po_box}


def parse(address1: Any, address2: Any = None, city: Any = None, state: Any = None,
          postal_code: Any = None, country_id: Any = None) -> Address:
    """An Autotask-shaped address → `Address`."""
    line1, line2 = clean(address1), clean(address2)
    if isinstance(country_id, bool) or not isinstance(country_id, (int, type(None))):
        try:
            country_id = int(str(country_id).strip())
        except (TypeError, ValueError):
            country_id = -1
    country = "US" if country_id in (None, US_COUNTRY_ID) else "other"
    street, unit, extra = line1, "", ""
    lead_unit = ""
    if not street and line2:
        street, line2 = line2, ""
    elif street and _WHOLE_UNIT.match(street) and line2 and not _WHOLE_UNIT.match(line2):
        # "Suite 400" + "700 Example Ln": the street is the second line.
        street, lead_unit, line2 = line2, street, ""
    elif street and _PO_BOX.match(street) and line2 and re.match(r"^\s*\d", line2) \
            and not _WHOLE_UNIT.match(line2):
        # "PO Box 12" + "100 Main St": the street is the second line.
        street, extra, line2 = line2, street, ""
    street, unit = split_unit(street)
    unit = " ".join(p for p in (unit, lead_unit) if p)
    if line2:
        if _WHOLE_UNIT.match(line2):
            unit = " ".join(p for p in (unit, line2) if p)
        else:
            extra = " ".join(p for p in (extra, line2) if p)
    if _WHOLE_UNIT.match(street):
        # Only a unit ("Suite 400" and nothing else): there is no street.
        street, unit = "", " ".join(p for p in (street, unit) if p)
    return Address(street=street, unit=unit, extra=extra[:MAX_PART], city=clean(city),
                   state=state_code(state), zip=zip5(postal_code), country=country,
                   po_box=bool(_PO_BOX.match(street)))


def name_tokens(*names: Optional[str]) -> set[str]:
    """Lower-case word tokens of names, for the conservative site matching."""
    out: set[str] = set()
    for n in names:
        out.update(w for w in re.split(r"[^a-z0-9]+", clean(n).lower()) if w)
    return out
