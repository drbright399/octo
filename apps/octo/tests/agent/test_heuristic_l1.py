"""Tests for the pure heuristic L1 triage engine (Task #119a).

Every rule path and its boundary conditions. The engine is pure, so
these are plain input→output assertions — no fixtures, no DB.
"""

from __future__ import annotations

import pytest

from apps.octo.agent.heuristic_l1 import (
    RECUR_NOISE_THRESHOLD,
    RECUR_PATTERN_THRESHOLD,
    TriageDecision,
    TriageFeatures,
    triage,
)


def _f(**kw) -> TriageFeatures:
    """Build features with sane defaults; override per test."""
    base = dict(severity="medium", has_indicator=False)
    base.update(kw)
    return TriageFeatures(**base)


# --- Rule 1: known false positive ------------------------------------------

def test_known_fp_always_noise_even_at_critical():
    # FP rule wins over everything, including critical severity.
    d = triage(_f(severity="critical", known_false_positive=True))
    assert d.disposition == "noise"
    assert d.confidence >= 0.9
    assert "false-positive" in d.rationale.lower()


# --- Rule 2: critical / high → escalate ------------------------------------

@pytest.mark.parametrize("sev", ["critical", "high"])
def test_high_and_critical_escalate(sev):
    d = triage(_f(severity=sev))
    assert d.disposition == "escalate"
    assert d.suggested_severity == sev


def test_critical_beats_recurrence_noise():
    # A critical event seen many times must NOT be suppressed as noise.
    d = triage(_f(severity="critical", recurrence_count=999))
    assert d.disposition == "escalate"


def test_high_indicator_mentioned_in_rationale():
    d = triage(_f(severity="high", has_indicator=True, indicator_hits=3))
    assert d.disposition == "escalate"
    assert "indicator" in d.rationale.lower()


# --- Rule 3: recurring low/info → noise ------------------------------------

@pytest.mark.parametrize("sev", ["info", "low"])
def test_recurring_low_is_noise_at_threshold(sev):
    d = triage(_f(severity=sev, recurrence_count=RECUR_NOISE_THRESHOLD))
    assert d.disposition == "noise"
    assert str(RECUR_NOISE_THRESHOLD) in d.rationale


def test_just_below_recur_noise_threshold_low_no_indicator_falls_to_noise_rule7():
    # 1 below threshold: rule 3 doesn't fire. A low event with no indicator
    # still lands as noise via rule 7 (but with the single-event rationale).
    d = triage(_f(severity="low", recurrence_count=RECUR_NOISE_THRESHOLD - 1,
                  has_indicator=False))
    assert d.disposition == "noise"
    assert "single event" in d.rationale.lower()


# --- Rule 4: recurring medium → pattern ------------------------------------

def test_recurring_medium_is_pattern():
    d = triage(_f(severity="medium", recurrence_count=RECUR_PATTERN_THRESHOLD))
    assert d.disposition == "pattern"
    assert d.suggested_severity == "medium"  # severity unchanged


def test_recurring_medium_pattern_beats_indicator_escalate():
    # Order: pattern (rule 4) is checked before indicator-escalate (rule 5).
    d = triage(_f(severity="medium", recurrence_count=RECUR_PATTERN_THRESHOLD,
                  has_indicator=True, indicator_hits=2))
    assert d.disposition == "pattern"


# --- Rule 5: medium + known indicator → escalate ---------------------------

def test_medium_with_indicator_hit_escalates():
    d = triage(_f(severity="medium", has_indicator=True, indicator_hits=1,
                  recurrence_count=0))
    assert d.disposition == "escalate"
    assert d.suggested_severity == "high"


# --- Rule 6: info single → noise -------------------------------------------

def test_info_single_is_noise():
    d = triage(_f(severity="info"))
    assert d.disposition == "noise"


# --- Rule 7: low, no indicator → noise -------------------------------------

def test_low_no_indicator_is_noise():
    d = triage(_f(severity="low", has_indicator=False))
    assert d.disposition == "noise"


# --- Rule 8: ambiguous → uncertain (the LLM hand-off) ----------------------

def test_single_medium_is_uncertain():
    d = triage(_f(severity="medium", recurrence_count=0, has_indicator=False))
    assert d.disposition == "uncertain"
    assert d.confidence <= 0.5  # deliberately low — defers to LLM/analyst


def test_low_with_novel_indicator_is_uncertain():
    # Low severity but carries an indicator never seen before (hits=0):
    # not clearly noise, not clearly escalate → uncertain.
    d = triage(_f(severity="low", has_indicator=True, indicator_hits=0,
                  recurrence_count=0))
    assert d.disposition == "uncertain"


# --- Decision shape --------------------------------------------------------

def test_note_text_prefixes_disposition():
    d = triage(_f(severity="critical"))
    assert d.note_text() == f"[escalate] {d.rationale}"


def test_decision_is_frozen():
    d = triage(_f(severity="info"))
    with pytest.raises(Exception):
        d.disposition = "escalate"  # type: ignore[misc]


def test_confidence_always_in_range():
    # Sweep a broad matrix; confidence must always be a valid probability.
    for sev in ["info", "low", "medium", "high", "critical"]:
        for rec in [0, RECUR_PATTERN_THRESHOLD, RECUR_NOISE_THRESHOLD, 50]:
            for hits in [0, 1, 9]:
                for ind in [True, False]:
                    for fp in [True, False]:
                        d = triage(TriageFeatures(
                            severity=sev, has_indicator=ind,
                            indicator_hits=hits, recurrence_count=rec,
                            known_false_positive=fp,
                        ))
                        assert 0.0 <= d.confidence <= 1.0
                        assert d.disposition in (
                            "noise", "pattern", "escalate", "uncertain")
                        assert isinstance(d, TriageDecision)


def test_determinism_same_input_same_output():
    f = _f(severity="medium", recurrence_count=2, has_indicator=True,
           indicator_hits=1)
    assert triage(f) == triage(f)


# --- Rule 1b: a vendor-reported closure (v0.11 R2) ---------------------------

def test_a_vendor_closure_is_a_no_action_note_referencing_the_open_row():
    from apps.octo.agent.heuristic_l1 import VendorClosure

    d = triage(_f(severity="medium", vendor_closure=VendorClosure(
        vendor="RocketCyber", status="resolved", incident_id="5001", open_event_id=12)))
    assert d.disposition == "noise" and d.disposition != "uncertain"
    assert d.suggested_severity == "medium" and d.confidence >= 0.9
    assert d.rationale == (
        "RocketCyber reports incident 5001 resolved — the closure of the open incident "
        "recorded as event #12. Vendor-reported closure; no action needed.")


def test_a_vendor_closure_without_its_open_row_says_so():
    from apps.octo.agent.heuristic_l1 import VendorClosure

    d = triage(_f(severity="medium", recurrence_count=RECUR_PATTERN_THRESHOLD + 5,
                  vendor_closure=VendorClosure(vendor="RocketCyber", status="suppressed",
                                               incident_id="5002")))
    assert d.disposition == "noise"      # not "pattern" either
    assert "its open record is not in this tenant's store" in d.rationale
    assert "suppressed" in d.rationale


def test_a_closure_the_vendor_rates_high_still_escalates():
    from apps.octo.agent.heuristic_l1 import VendorClosure

    d = triage(_f(severity="high", vendor_closure=VendorClosure(
        vendor="RocketCyber", status="resolved", incident_id="5003")))
    assert d.disposition == "escalate"
