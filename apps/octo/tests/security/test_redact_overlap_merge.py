"""Redaction scrubs the UNION of overlapping hits (round-5 verifier finding).

A scan keeps the higher-priority hit where two overlap; redaction must not:
an assignment scrubbed to the end of its word with a token shape inside that
word has to scrub both, or part of a secret stays in clear in job output.
Also: a Slack token or webhook signing secret right after '-' or '/' is still
found and redacted (the quadratic fix bounds the value instead of narrowing
the lookbehind), and control characters in a printed file name are escaped.
"""
from __future__ import annotations

import base64
import time

from apps.octo.security import secret_patterns as sp
from apps.octo.tests.security import fakes

PW = "Xk9" + fakes.rand("merge-pw", 9) + "#2q"


def _slack(label: str = "merge") -> str:
    digits = "0123456789"
    return ("xox" + "b-" + fakes.rand(f"{label}-d1", 12, digits) + "-" + fakes.rand(f"{label}-d2", 12, digits)
            + "-" + fakes.rand(f"{label}-s", 24))


def _whsec(label: str = "merge") -> str:
    return "whs" + "ec_" + base64.b64encode(fakes.key_bytes(f"{label}-whsec", 24)).decode()


def _gh() -> str:
    return "gh" + "p_" + fakes.rand("merge-gh", 36)


def _assert_gone(out: str, *secrets: str) -> None:
    for s in secrets:
        for i in range(0, len(s) - 5):
            assert s[i:i + 6] not in out, "a 6-character piece of a secret survived redaction"


def test_assignment_tail_and_inner_token_are_both_scrubbed():
    for line in (
        f"password={PW}&token={_gh()}",
        "--pass" + f"word={PW},{_slack()}",  # built so this file does not carry a flag=value line
        f"API_KEY={PW};{_whsec()}",
        f"DATTO_API_SECRET={PW}{_gh()}",
    ):
        out, n = sp.redact(f"job output: {line} done")
        assert n >= 1
        _assert_gone(out, PW, _gh(), _slack(), _whsec())
        assert out.startswith("job output: ") and out.endswith(" done")


def test_merged_span_is_labelled_and_idempotent():
    text = f"x password={PW}&token={_gh()} y"
    out, _ = sp.redact(text)
    assert "[REDACTED:" in out
    assert sp.redact(out) == (out, 0)


def test_separate_secrets_stay_separate_redactions():
    out, n = sp.redact(f"a {_gh()} b {_slack()} c")
    assert n == 2
    assert out.startswith("a [REDACTED:") and " b [REDACTED:" in out and out.endswith(" c")


def test_slack_and_whsec_after_dash_or_slash_are_still_found_and_redacted():
    for sep in ("-", "/", "+", "_x-"):
        for tok in (_slack("dash"), _whsec("dash")):
            text = f"id{sep}{tok} end"
            out, n = sp.redact(text)
            assert n >= 1, sep
            _assert_gone(out, tok)
            assert any(h.secret for h in sp.find_hits(text))


def test_bounded_token_runs_stay_linear():
    for head in ("xox" + "b-", "whs" + "ec_"):
        run = (head + "a1-") * 20000  # ~100 kB of rejected candidates
        t0 = time.process_time()
        sp.find_hits(run)
        sp.redact(run)
        assert time.process_time() - t0 < 2.0, head


def test_control_characters_in_printed_names_are_escaped():
    from apps.octo.tests.security import hostile
    ss = hostile._scanner()
    shown = ss.printable("x\x1b[2K\x1b[1Ay\r\x7f\x9b.txt")
    assert "\x1b" not in shown and "\r" not in shown and "\x7f" not in shown and "\x9b" not in shown
    assert "\\x1b" in shown and shown.startswith("x") and shown.endswith(".txt")
    assert ss.printable("tab\tok\nline") == "tab\tok\nline"
