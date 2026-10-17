"""What a RocketCyber incident row SAYS — headline, detail, site — and that
hostile vendor text comes out bounded, printable and without markup."""
from __future__ import annotations

import time

import pytest

from apps.octo.adapters.rocketcyber.presentation import (
    EVENT_TYPE,
    present_incident,
    psa_ticket,
)
from apps.octo.adapters.rocketcyber.tests.fake_rocketcyber import incident, resolved
from apps.octo.ingest.presentation import DETAIL_MAX, DETAIL_MAX_LINES, HEADLINE_MAX


def _printable(text: str) -> bool:
    return all(ch.isprintable() or ch == "\n" for ch in text)


# ---------------------------------------------------------------------------
# The ordinary case
# ---------------------------------------------------------------------------

def test_open_incident_headline_and_detail():
    shown = present_incident(incident(3, event_count=4, psa_id="T20000101.0001"))
    assert shown.event_type == EVENT_TYPE
    assert shown.headline == "RocketCyber · Suspicious PowerShell execution 3"
    assert shown.site == "Acme Corp" and shown.device is None and not shown.fallback
    lines = shown.detail.split("\n")
    # Markdown reduced to its words: heading marks, bold, table, bullets, code.
    assert lines[0] == "Summary"
    assert lines[1] == "Suspicious PowerShell execution was observed on WS-EXAMPLE-01."
    assert "Field: Value" in lines and "Host: WS-EXAMPLE-01" in lines and "User: alice" in lines
    assert "• Parent process: winword.exe" in lines
    # Remediation, marked, a few lines; a markdown link keeps its words only.
    rem = [ln for ln in lines if ln.startswith("Remediation:")]
    assert rem == ["Remediation: • Isolate the device."]
    assert "• Review the process tree." in lines
    assert "portal.example.test" not in shown.detail
    # The facts line closes the block.
    assert lines[-1] == "Customer: Acme Corp · 4 events · PSA ticket T20000101.0001"


def test_resolved_and_suppressed_are_labelled_in_the_headline():
    closed = present_incident(resolved(incident(1)))
    assert closed.headline == "RocketCyber · Suspicious PowerShell execution 1 — resolved"
    assert "Status: resolved" in closed.detail and "Resolved 20" in closed.detail
    muted = present_incident({**incident(1), "status": "suppressed"})
    assert muted.headline.endswith(" — suppressed")
    odd = present_incident({**incident(1), "status": "Escalated‮"})
    assert odd.headline.endswith(" — escalated")


def test_the_status_suffix_survives_a_very_long_title():
    raw = resolved(incident(1, title="Very long title " * 40))
    shown = present_incident(raw)
    assert len(shown.headline) <= HEADLINE_MAX
    assert shown.headline.endswith("… — resolved")


def test_a_description_line_repeating_the_title_is_skipped():
    raw = incident(1, title="Brute force detected", description="Brute force detected\nFrom 203.0.113.9")
    assert present_incident(raw).detail.split("\n")[0] == "From 203.0.113.9"


def test_no_title_falls_back_to_the_incident_id():
    raw = incident(1, title="")
    shown = present_incident(raw)
    assert shown.headline == "RocketCyber incident 5001" and shown.fallback is True
    assert present_incident({}).headline == "RocketCyber incident"
    assert present_incident(None).headline == "RocketCyber incident"
    assert present_incident("junk").event_type == EVENT_TYPE


def test_psa_ticket():
    assert psa_ticket(incident(1, psa_id="T1")) == "T1"
    assert psa_ticket({"psaId": 12345}) == "12345"
    assert psa_ticket({"psaId": None}) is None
    assert psa_ticket({"psaId": True}) is None
    assert psa_ticket({"psaId": "T1\x00‮X"}) == "T1X"


# ---------------------------------------------------------------------------
# Hostile vendor text
# ---------------------------------------------------------------------------

HOSTILE = (
    "<script>alert(1)</script><img src=x onerror=alert(2)>\n"
    "<b>bold</b> <a href=\"https://evil.example.test\">click</a><br>next line\n"
    "\x1b[31mANSI\x1b[0m \x00NUL ​zero​width ‮RTL-OVERRIDE‬\n"
    "[Reset your password here](https://evil.example.test/login) now\n"
    "![tracker](https://evil.example.test/pixel.gif)\n"
    "Contact <admin@example.test> about <WS-EXAMPLE-02>\n"
    "&lt;b&gt;escaped&lt;/b&gt; &amp; done\n"
    "\r\n\r\n---\r\n| | |\r\n***\r\n"
    "Line separator para\x85nel\n"
)


def test_hostile_description_is_reduced_to_printable_bounded_words():
    shown = present_incident(incident(1, description=HOSTILE, remediation=""))
    detail = shown.detail
    assert _printable(detail) and _printable(shown.headline)
    for gone in ("<script>", "</script>", "<img", "<b>bold", "<a ", "\x1b", "\x00",
                 "​", "‮", "evil.example.test", "](", " ", "\x85"):
        assert gone not in detail
    assert "alert(1)" in detail                    # the words stay, as text
    assert "bold click" in detail and "next line" in detail
    assert "Reset your password here now" in detail
    # Angle-bracketed DATA is not markup.
    assert "<admin@example.test>" in detail and "<WS-EXAMPLE-02>" in detail
    # An ESCAPED tag was meant to be shown literally: decoded AFTER the tag
    # pass, it stays as the text it is (the console renders text nodes).
    assert "<b>escaped</b> & done" in detail
    assert "---" not in detail.split("\n") and "***" not in detail.split("\n")


def test_hostile_title_cannot_break_the_headline_onto_two_lines():
    raw = incident(1, title="Fake\nRocketCyber · Password reset required\r\x00‮")
    shown = present_incident(raw)
    assert "\n" not in shown.headline and "\r" not in shown.headline
    assert _printable(shown.headline)
    assert shown.headline.startswith("RocketCyber · Fake RocketCyber")


def test_huge_description_and_remediation_are_bounded_and_the_facts_survive():
    raw = incident(
        1,
        description="\n".join(f"line {n} " + "x" * 300 for n in range(5_000)),
        remediation="\n".join(f"step {n} " + "y" * 300 for n in range(5_000)),
        psa_id="T42",
    )
    started = time.monotonic()
    shown = present_incident(raw)
    assert time.monotonic() - started < 1.0
    lines = shown.detail.split("\n")
    assert len(shown.detail) <= DETAIL_MAX and len(lines) <= DETAIL_MAX_LINES
    assert "…" in lines                              # the cut is visible
    assert any(ln.startswith("Remediation: step 0") for ln in lines)
    assert lines[-1] == "Customer: Acme Corp · 1 event · PSA ticket T42"


def test_one_enormous_line_is_bounded():
    shown = present_incident(incident(1, description="z" * 100_000, remediation="r" * 100_000))
    assert len(shown.detail) <= DETAIL_MAX
    assert all(len(ln) <= 240 for ln in shown.detail.split("\n"))


@pytest.mark.parametrize(
    "field_value",
    [None, 42, ["a", "b"], {"nested": "x"}, True, "", "   \n\t  "],
)
def test_non_text_fields_never_raise(field_value):
    raw = incident(1)
    for key in ("title", "description", "remediation", "accountName", "status",
                "eventCount", "psaId", "resolvedAt"):
        raw[key] = field_value
    shown = present_incident(raw)
    assert shown.headline and shown.event_type == EVENT_TYPE
    assert _printable(shown.detail)


def test_a_pathological_markdown_link_does_not_backtrack():
    evil = "[" * 5_000 + "a](" + "(" * 5_000
    started = time.monotonic()
    present_incident(incident(1, description=evil * 3))
    assert time.monotonic() - started < 1.0
