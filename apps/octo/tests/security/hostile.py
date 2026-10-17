"""Hostile inputs for every detector and every program-check regex, and a
timed runner for them (``test_guardrails_v7`` runs it in a subprocess).

A catastrophic regex cannot be stopped from inside the process (the ``re``
engine never checks for signals), so the runner is its own process: it
prints one JSON line per call as it goes, and the test kills it at a
deadline and blames whatever was running.

The inputs are generated from the detectors themselves, so a detector added
later is covered without editing this file:

* seeds: each detector's needles, two strings sampled from its pattern (an
  alternation factored by first letter has no whole word among its
  literals) and its longest literal runs (``sshpass``, ``-pw``, ``?key=``,
  ``whsec_``...); each repeated glued, spaced and assigned, one character
  short (near misses), and followed by long runs of the characters patterns
  repeat (letters, digits, ``- = / \\ : . %``, quotes, escaped newlines);
* option lists: a program, then 40 / 12 500 option tokens, then a near miss
  of the word it waits for (``docker --a --a ... --loginx -p <pw>``): the
  shape of the docker / podman / nerdctl login ReDoS;
* runs of candidates in one token (v8): what precedes the value in a sampled
  match (``--password=``, ``xoxb-``, ``whsec_``), then a value a check
  refuses (a path, ``[REDACTED:x]``, ``C:\\``, ``HKLM\\``, ``example``) or
  keeps (a password shape), then a joiner, repeated. A refused candidate is
  searched again from one character after its start, and an accepted one is
  scrubbed to the end of its word: an unbounded value, or a start inside
  another candidate's value, makes either quadratic;
* the same runs after the options and assignments of job output
  (``--key=``, ``/ACCT_KEY=``, ``DATTO_API_KEY=``, ``AccountKey : ``...)
  through the whole pipeline, the heaviest at 400 kB (one job-output
  stream's cap) through redact and the normaliser;
* 50 kB lines, and each detector's heaviest stretched to 200 kB;
* the whole pipeline: find_hits, redact, the Datto job-output normaliser and
  the scanner's report (scan_text: its masked excerpt of the line);
* every other module-level regex of secret_patterns (the checks' and
  redaction's helpers: the Format-List value column, the wrapped tail...)
  SEARCHED on 50 kB runs, blank runs included: a regex that is linear only
  when matched at a line start (an unbounded ``[ \\t]*`` before a part that
  can fail, CodeQL py/polynomial-redos) is caught here, and Format-List
  property and continuation lines go through the whole pipeline.

Every value here is synthetic.
"""
from __future__ import annotations

import json
import random
import re
import sys
import time
from typing import Iterable, Iterator

try:
    import re._parser as _parser  # Python 3.11+
except ImportError:  # pragma: no cover
    import sre_parse as _parser  # type: ignore[no-redef]

SIZE = 50_000
BIG = 200_000
PW = "Zq7" + "Kp93mXv" + "2Lw"  # a synthetic password shape, assembled
#: CPU seconds one call may take per 50 kB of input.
BUDGET = 0.5
# What patterns repeat: a run of each follows a seed.
RUNS = ("a", "A1", "-", "=", "/", "\\", ":", ".", "%", " x", "\\n", "'", "?")
#: The whole pipeline runs at 200 kB on this many of the heaviest inputs.
BIG_INPUTS = 8
#: One job-output stream's cap (apps.octo.adapters.datto.job_output).
JOB = 400_000
#: A value after a candidate's head, and what joins it to the next one (see
#: rejected_runs): refused by the checks (empty, a path, a redaction marker,
#: a drive, a registry hive, a placeholder word, a mask) or kept (a password
#: shape, short and long).
VALUE_RUNS = (("", ""), ("", "-"), ("/", ""), ("[REDACTED:x]", ""), ("C:\\", "&"), ("HKLM\\", ";"),
              ("example", ")"), ("***", "/"), (PW[:8], ";"), (PW * 3, "-"))
#: Options and assignments job output carries (the redact-only detectors
#: among them): each followed by every VALUE_RUNS pair, repeated, through
#: the whole pipeline.
OPTION_HEADS = ("--key=", "--license ", "--password=", "--token ", "/ACCT_KEY=", "-OrgKey ",
                "DATTO_API_KEY=", "ORG_KEY=", "password=", "AccountKey : ", "client_secret: ",
                "Signing key: ", "-p ", "/p:")
#: Whole-pipeline shapes that are no head + value run: a flood of private-key
#: headers with no END line, and "eyJ" runs before long tokens (the JWT
#: prefix test behind each high-entropy candidate).
PIPELINE_SHAPES = (
    ("pem-headers", "-----BEGIN " + "PRIVATE KEY-----\n/\n"),
    ("jwt-prefix-window", "eyJ" * 1300 + " " + " ".join(PW * 3 + str(i) for i in range(90)) + " "),
    # Format-List: a value at the end of a tab-indented property line (the
    # value column is read for it), and a value wrapped onto continuation
    # lines under blank-indented lines that are no property.
    ("format-list-tab-indent", "\t" * 4000 + "AccountKey :\t" + PW + "\n"),
    ("format-list-continuations", "PathName : x --license_key " + PW * 3 + "\n"
     + (" " * 11 + PW + "\n") * 16 + "\t" * 3000 + "x\t" * 60 + "\n"),
)
#: Searched with RUNS by every helper regex (helper_inputs): blank runs, and
#: a name before blanks and a colon (the Format-List ReDoS shapes).
HELPER_RUNS = ("\t", " ", " \t", "\t\n", "a\t", "a :", "a\t:", "x\n")
# How many seeds per detector (see seed_list).
SEEDS = 5


def budget(text: str) -> float:
    return BUDGET * max(1.0, len(text) / SIZE)


def literals(pattern: str, flags: int = 0) -> list[str]:
    """Literal runs of 2+ characters anywhere in a regex."""
    try:
        parsed = _parser.parse(pattern, flags)
    except Exception:  # pragma: no cover - a pattern compiled, so it parses
        return []
    found: set[str] = set()

    def walk(sub) -> None:
        run: list[str] = []
        for op, av in sub:
            if op is _parser.LITERAL:
                run.append(chr(av))
                continue
            if len(run) >= 2:
                found.add("".join(run))
            run = []
            stack = [av]
            while stack:
                item = stack.pop()
                if isinstance(item, _parser.SubPattern):
                    walk(item)
                elif isinstance(item, (list, tuple)):
                    stack.extend(item)
        if len(run) >= 2:
            found.add("".join(run))

    walk(parsed)
    return sorted(found, key=lambda s: (-len(s), s))


_ASCII = [chr(c) for c in range(32, 127)]


#: Marks sample() puts in its output (see heads()).
VALUE_MARK = "\x00"
REPEAT_MARK = "\x01"


def sample(pattern: str, flags: int, rng: random.Random, *, most: int = 3,
           marks: frozenset[int] = frozenset()) -> str:
    """A string shaped like a match of ``pattern`` (branches picked at
    random, repeats short, lookbehinds and negative lookaheads skipped; a
    positive lookahead defines its groups for a later back-reference, the
    atomic ``(?=(?P<n>...))(?P=n)``): what a hostile line is built from when
    the pattern's literals are fragments (an alternation factored by first
    letter has no whole word in it). ``marks``: group numbers whose text is
    preceded by VALUE_MARK; the first unbounded repeat is preceded by
    REPEAT_MARK (only with ``marks``)."""
    parsed = _parser.parse(pattern, flags)
    groups: dict[int, str] = {}
    state = {"repeat": not marks}

    def pick_in(items) -> str:
        allowed: list[str] = []
        negate = False
        for op, av in items:
            if op is _parser.NEGATE:
                negate = True
            elif op is _parser.LITERAL:
                allowed.append(chr(av))
            elif op is _parser.RANGE:
                lo, hi = av
                allowed += [chr(c) for c in range(lo, min(hi, lo + 95) + 1)]
            elif op is _parser.CATEGORY:
                name = str(av).lower()
                allowed += list("aZ9_") if "word" in name else list("07") if "digit" in name else [" "]
        if negate:
            pool = [c for c in _ASCII if c not in allowed] or ["~"]
            return rng.choice(pool)
        return rng.choice(allowed or ["x"])

    def gen(sub) -> str:
        out: list[str] = []
        for op, av in sub:
            if op is _parser.LITERAL:
                out.append(chr(av))
            elif op is _parser.NOT_LITERAL:
                out.append("x" if chr(av) != "x" else "y")
            elif op is _parser.ANY:
                out.append("x")
            elif op is _parser.IN:
                out.append(pick_in(av))
            elif op is _parser.BRANCH:
                out.append(gen(rng.choice(av[1])))
            elif op is _parser.SUBPATTERN:
                text = gen(av[-1])
                if av[0] is not None:
                    groups[av[0]] = text
                out.append((VALUE_MARK if av[0] in marks else "") + text)
            elif op in (_parser.MAX_REPEAT, _parser.MIN_REPEAT, getattr(_parser, "POSSESSIVE_REPEAT", None)):
                lo, hi, item = av
                if (hi is _parser.MAXREPEAT or hi >= 100) and not state["repeat"]:  # long bounded repeats too
                    state["repeat"] = True
                    out.append(REPEAT_MARK)
                hi = lo + most if hi is _parser.MAXREPEAT else min(hi, lo + most)
                out.append("".join(gen(item) for _ in range(rng.randint(lo, max(lo, hi)))))
            elif op is _parser.ASSERT and av[0] == 1:
                gen(av[1])  # a lookahead: its groups are defined, nothing is written
            elif op is getattr(_parser, "ATOMIC_GROUP", None):
                out.append(gen(av))
            elif op is _parser.GROUPREF:
                out.append(groups.get(av, ""))
            elif op is _parser.GROUPREF_EXISTS:
                out.append(gen(av[1]))
            # AT, ASSERT, ASSERT_NOT: nothing to write
        return "".join(out)

    return gen(parsed)


def seed_list(rx, needles: tuple[str, ...], label: str) -> list[str]:
    """Two needles, two sampled matches (blanks taken out, so a repeat of one
    is a run of candidates), the longest literals, the other needles."""
    rng = random.Random(f"hostile:{label}")
    found = list(needles[:2])
    found += ["".join(sample(rx.pattern, rx.flags, rng).split())[:80] for _ in range(2)]
    found += literals(rx.pattern, rx.flags) + list(needles[2:])
    out: list[str] = []
    for s in found:
        s = s.strip()
        if len(s) >= 2 and s not in out:
            out.append(s)
    return out[:SEEDS] or ["ab"]


def seeds_of(detector) -> list[str]:
    return seed_list(detector.pattern, detector.needles, detector.name)


def _value_groups(detector) -> frozenset[int]:
    """The group numbers of the detector's value (all of them for an
    assignment's alternatives)."""
    from apps.octo.security import secret_patterns as sp

    group = detector.group
    names = sp._VALUE_GROUPS if group == "value" else group if isinstance(group, tuple) else (group,)
    index = detector.pattern.groupindex
    return frozenset(index[n] if isinstance(n, str) else n for n in names
                     if (n in index if isinstance(n, str) else n > 0))


def heads(detector) -> list[str]:
    """What precedes the value in two sampled matches of the detector: the
    text before its value group, or, for a token shape, before its first
    unbounded repeat (``--password=``, ``xoxb-``, ``whsec_``)."""
    rng = random.Random(f"hostile-heads:{detector.name}")
    marks = _value_groups(detector) or frozenset({-1})  # -1: no group, the repeat mark only
    out: list[str] = []
    for _ in range(2):
        text = sample(detector.pattern.pattern, detector.pattern.flags, rng, marks=marks)
        cut = [i for i in (text.find(VALUE_MARK), text.find(REPEAT_MARK)) if i != -1]
        head = text[:min(cut)] if cut else ""
        head = head.replace(VALUE_MARK, "").replace(REPEAT_MARK, "")[-40:]
        if head.strip() and head not in out:
            out.append(head)
    return out


def rejected_runs(head: str, size: int = SIZE) -> Iterator[tuple[str, str]]:
    """``(label, text)``: ``<head><value><joiner>`` repeated in one token for
    each VALUE_RUNS pair, then a placeholder word (a run of glued heads is
    one candidate whose value is all of them: the word makes the check
    refuse it)."""
    for value, joiner in VALUE_RUNS:
        yield f"rejected{value[:12]!r}{joiner!r}", _fill(head + value + joiner, size) + "example"


def _fill(unit: str, size: int) -> str:
    return (unit * (size // max(1, len(unit)) + 1))[:size]


def shapes(seed: str, size: int = SIZE) -> Iterator[tuple[str, str]]:
    """``(label, text)`` hostile lines built around one seed."""
    yield "glued", _fill(seed, size)
    yield "spaced", _fill(seed + " ", size)
    yield "assigned", _fill(seed + "=", size)
    yield "colon", _fill(seed + ":", size)
    if len(seed) > 2:
        yield "near-miss", _fill(seed[:-1] + " ", size)
        yield "near-miss-glued", _fill(seed[:-1] + "x", size)
    for run in RUNS:
        yield f"run{run!r}", seed + " " + _fill(run, size)
        yield f"seed{run!r}", seed + _fill(run, size)


def option_lists(program: str, word: str, option: str = "-p") -> Iterator[tuple[str, str]]:
    """``<program> --a ... --a --<word>x <option> <pw>``: an option list
    that ends in a near miss of the word the program check waits for."""
    for k in (40, SIZE // 4):
        yield f"options{k}", f"{program}{' --a' * k} --{word}x {option} {PW}"
        yield f"short-options{k}", f"{program}{' -a' * k} {word}x {option} {PW}"
        yield f"valued-options{k}", f"{program}{' --a=b' * k} {word}x {option} {PW}"


def detector_inputs(detector) -> list[tuple[str, str]]:
    """Every hostile line for one detector (deduplicated)."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def add(items: Iterable[tuple[str, str]], prefix: str) -> None:
        for label, text in items:
            if text not in seen:
                seen.add(text)
                out.append((f"{prefix}:{label}", text))

    for seed in seeds_of(detector):
        add(shapes(seed), seed)
    for needle in detector.needles[:3]:
        add(option_lists(needle, "login"), needle)
        add(option_lists(needle, needle), needle)
    for head in heads(detector):
        add(rejected_runs(head), head)
    return out


def pipeline_inputs(size: int = SIZE) -> list[tuple[str, str]]:
    """The job-output runs: every OPTION_HEADS entry with every VALUE_RUNS
    pair, and the PIPELINE_SHAPES."""
    out = [(f"{head}:{label}", text) for head in OPTION_HEADS for label, text in rejected_runs(head, size)]
    return out + [(label, _fill(unit, size)) for label, unit in PIPELINE_SHAPES]


def program_regexes(sp) -> list[tuple[str, object]]:
    """``(name, compiled)`` for every program check and every "what must
    follow" check of the cli-password families."""
    out = []
    for family, _pattern, _groups, program, _needles, after in sp._CLI_FAMILIES:
        if program is not None:
            out.append((f"{family}:program", program[0]))
        if after is not None:
            out.append((f"{family}:after", after))
    return out


def helper_regexes(sp) -> list[tuple[str, object]]:
    """``(name, compiled)`` for every module-level regex of secret_patterns
    that is no detector's pattern (a regex added there later is covered
    without editing this file)."""
    detectors = {id(d.pattern) for d in sp.DETECTORS}
    return [(f"helper:{name}", rx) for name, rx in sorted(vars(sp).items())
            if isinstance(rx, re.Pattern) and id(rx) not in detectors]


def helper_inputs(rx, label: str) -> list[tuple[str, str]]:
    """50 kB runs of RUNS and HELPER_RUNS, then the regex's own seeds'
    shapes at 5 kB (as for the program checks)."""
    out = [(f"run{run!r}", _fill(run, SIZE)) for run in RUNS + HELPER_RUNS]
    for seed in seed_list(rx, (), label):
        out += [(f"{seed}:{name}", text) for name, text in shapes(seed, 5_000)]
    return out


def program_inputs(rx, label: str) -> list[tuple[str, str]]:
    seeds = seed_list(rx, (), label)
    out: list[tuple[str, str]] = []
    for seed in seeds:
        for word in ("login", seed):
            for k in (40, 150, 2_000):
                out.append((f"{seed}:options{k}", f"{seed}{' --a' * k} --{word}x"))
                out.append((f"{seed}:short-options{k}", f"{seed}{' -a' * k} {word}x"))
        out += [(f"{seed}:{label}", text) for label, text in shapes(seed, 5_000)]
    return out


def _scanner():
    """scripts/scan_sensitive.py as a module (it is a script, not a package)."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[4] / "scripts" / "scan_sensitive.py"
    spec = importlib.util.spec_from_file_location("scan_sensitive", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("scan_sensitive", module)  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


def _cpu(fn, *args) -> float:
    start = time.process_time()
    fn(*args)
    return time.process_time() - start


def run(only: set[str] | None = None) -> None:
    """Time every call, one JSON line each, flushed (a hang is attributed:
    its "start" line has no result line). The program checks and the helper
    regexes, searched on their hostile lines. Each detector alone on each of its
    hostile lines (scan and redact); then the whole pipeline (find_hits with
    the publish-only detectors, redact, the Datto job-output normaliser, the
    scanner's report with its masked excerpt) on
    the line that cost it most, and the detector alone on that line
    stretched to 200 kB; then the whole pipeline on the heaviest of those."""
    from apps.octo.adapters.datto.job_output import normalize_job_output
    from apps.octo.security import secret_patterns as sp

    ss = _scanner()
    lan = ".".join(("10", "20", "30", "40"))  # a reported hit: the line gets an excerpt

    def emit(**record) -> None:
        sys.stdout.write(json.dumps(record) + "\n")
        sys.stdout.flush()

    def timed(target: str, label: str, path: str, text: str, fn, *args) -> float:
        emit(target=target, input=label, path=path, size=len(text), start=True)
        seconds = _cpu(fn, *args)
        emit(target=target, input=label, path=path, size=len(text), seconds=seconds)
        return seconds

    def pipeline(target: str, label: str, text: str) -> float:
        line = f"{text} {lan}\n"  # the scanner's report: find_hits, then the masked excerpt
        return (timed(target, label, "find_hits", text, lambda: sp.find_hits(text, ctx, "scan", publish=True))
                + timed(target, label, "redact", text, sp.redact, text)
                + timed(target, label, "normalize", text, normalize_job_output,
                        {"stdout": text, "stderr": text[:SIZE // 10], "exit": 0})
                + timed(target, label, "scan_text", line,
                        lambda: ss.scan_text("ops/hostile.txt", line, publish=True)))

    ctx = sp.Context(path="ops/hostile.txt")
    for name, rx in program_regexes(sp):
        if not only or name in only:
            for label, text in program_inputs(rx, name):
                timed(name, label, "program", text, rx.search, text)
    # Searched, never matched at a start: the worst way a regex is applied.
    for name, rx in helper_regexes(sp):
        if not only or name in only:
            for label, text in helper_inputs(rx, name):
                timed(name, label, "search", text, rx.search, text)
    heaviest: list[tuple[float, str, str, str]] = []
    for d in sp.DETECTORS:
        if only and d.name not in only:
            continue
        costs: list[tuple[float, str, str]] = []
        for label, text in detector_inputs(d):
            total = sum(timed(d.name, label, f"detector:{purpose}", text, sp.detector_hits, d, text, ctx, purpose)
                        for purpose in ("scan", "redact"))
            costs.append((total, label, text))
        _, label, text = max(costs, key=lambda c: c[0])
        total = pipeline(d.name, label, text)
        big = _fill(text, BIG)  # a quadratic shows here: 16 times the 50 kB cost
        for purpose in ("scan", "redact"):
            timed(d.name, f"{label}@200k", f"detector:{purpose}", big, sp.detector_hits, d, big, ctx, purpose)
        heaviest.append((total, d.name, f"{label}@200k", big))
    # The lines the whole pipeline found heaviest at 50 kB, at 200 kB.
    for _, target, label, text in sorted(heaviest, key=lambda h: -h[0])[:BIG_INPUTS]:
        pipeline(target, label, text)
    # Job output: option / assignment runs through every detector at once;
    # the heaviest at one stream's cap through redact and the normaliser.
    if not only or "job-output" in only:
        costs = []
        for label, text in pipeline_inputs():
            total = (timed("job-output", label, "find_hits", text,
                           lambda: sp.find_hits(text, ctx, "scan", publish=True))
                     + timed("job-output", label, "redact", text, sp.redact, text)
                     + timed("job-output", label, "normalize", text, normalize_job_output,
                             {"stdout": text, "stderr": "", "exit": 0}))
            costs.append((total, label, text))
        for _, label, text in sorted(costs, key=lambda c: -c[0])[:BIG_INPUTS]:
            big = _fill(text, JOB)
            timed("job-output", f"{label}@400k", "redact", big, sp.redact, big)
            timed("job-output", f"{label}@400k", "normalize", big, normalize_job_output,
                  {"stdout": big, "stderr": "", "exit": 0})
    emit(done=True)


if __name__ == "__main__":
    run(set(sys.argv[1:]) or None)
