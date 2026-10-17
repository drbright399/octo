"""Verifier-CLI smoke tests — confirm `scripts/verify_audit_chain.py`
correctly detects clean vs corrupted chains and exits with the right
status code.

The verifier delegates to `audit.verify()` (which is itself a
trust-load-bearing function — chain-link math). These tests aren't
re-testing the math; they're testing the file-walk + multi-chain
aggregation + exit-code semantics.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from apps.octo.auth import audit
from apps.octo.db import connect, transaction


SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "verify_audit_chain.py"


def _init_audit_db(p: Path) -> None:
    """Initialize an audit.db with the audit_log table schema. Mirrors
    what migration 002 produces in production but standalone for testing.
    `executescript` implicitly commits — no explicit transaction wrapper.
    """
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(p)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts              TEXT    NOT NULL,
                actor           TEXT    NOT NULL,
                actor_kind      TEXT    NOT NULL,
                action          TEXT    NOT NULL,
                target_kind     TEXT    NOT NULL,
                target_id       TEXT    NOT NULL,
                client_slug     TEXT    NOT NULL,
                before_state    TEXT,
                after_state     TEXT,
                reason          TEXT,
                request_id      TEXT    NOT NULL,
                prev_hash       TEXT    NOT NULL,
                row_hash        TEXT    NOT NULL
            );
        """)
    finally:
        conn.close()


def _append_some(p: Path, n: int) -> None:
    """Append n synthetic audit rows so the chain is non-empty."""
    conn = connect(p)
    try:
        for i in range(n):
            audit.append(conn, audit.AuditEntry(
                actor="test", actor_kind="system",
                action=f"test_action_{i}",
                target_kind="test", target_id=f"row-{i}",
                client_slug="global",
                after_state={"i": i},
                reason="smoke test",
                request_id=f"req-{i:04d}",
            ))
    finally:
        conn.close()


def _corrupt_chain(p: Path) -> None:
    """Flip one byte of row_hash mid-chain to break the link."""
    conn = connect(p)
    try:
        with transaction(conn):
            conn.execute(
                "UPDATE audit_log SET row_hash = 'ffffffffffffffff' "
                "|| substr(row_hash, 17) WHERE id = "
                "(SELECT MIN(id) FROM audit_log)",
            )
    finally:
        conn.close()


def _run_verifier(data_root: Path) -> tuple[int, dict | None]:
    """Run the CLI; return (exit_code, parsed_json_report_or_None).

    The verifier emits JSON on stdout for the normal walk paths. For
    early-exit failures (no audit.dbs found at all), it emits only an
    error to stderr and returns exit code 2 — in that case the parsed
    JSON is None.
    """
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--data-root", str(data_root),
         "--quiet"],
        capture_output=True, text=True,
    )
    if not result.stdout.strip():
        return result.returncode, None
    return result.returncode, json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def test_clean_global_chain_exits_zero(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    global_audit = data_root / "global" / "audit.db"
    _init_audit_db(global_audit)
    _append_some(global_audit, 5)

    code, report = _run_verifier(data_root)
    assert code == 0
    assert report["chains_total"] == 1
    assert report["chains_failed"] == 0
    assert report["results"][0]["ok"] is True
    assert report["results"][0]["row_count"] == 5
    assert report["results"][0]["error"] is None


def test_corrupted_chain_exits_one(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    global_audit = data_root / "global" / "audit.db"
    _init_audit_db(global_audit)
    _append_some(global_audit, 5)
    _corrupt_chain(global_audit)

    code, report = _run_verifier(data_root)
    assert code == 1
    assert report["chains_total"] == 1
    assert report["chains_failed"] == 1
    assert report["results"][0]["ok"] is False
    assert report["results"][0]["error"] is not None


def test_per_tenant_chains_also_walked(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    # one global + two tenants
    _init_audit_db(data_root / "global" / "audit.db")
    _append_some(data_root / "global" / "audit.db", 2)
    _init_audit_db(data_root / "clients" / "acme" / "audit.db")
    _append_some(data_root / "clients" / "acme" / "audit.db", 3)
    _init_audit_db(data_root / "clients" / "globex" / "audit.db")
    _append_some(data_root / "clients" / "globex" / "audit.db", 1)

    code, report = _run_verifier(data_root)
    assert code == 0
    assert report["chains_total"] == 3
    labels = sorted(r["label"] for r in report["results"])
    assert labels == ["global", "tenant:acme", "tenant:globex"]
    total_rows = sum(r["row_count"] for r in report["results"])
    assert total_rows == 6


def test_missing_data_root_exits_two(tmp_path: Path) -> None:
    # Empty data root, no audit.dbs anywhere.
    code, _ = _run_verifier(tmp_path / "data")
    assert code == 2


def test_one_tenant_bad_other_good(tmp_path: Path) -> None:
    """Mixed result: verifier exits 1 (something failed) but the other
    chains' clean results still appear in the report."""
    data_root = tmp_path / "data"
    _init_audit_db(data_root / "global" / "audit.db")
    _append_some(data_root / "global" / "audit.db", 4)
    _init_audit_db(data_root / "clients" / "acme" / "audit.db")
    _append_some(data_root / "clients" / "acme" / "audit.db", 4)
    _corrupt_chain(data_root / "clients" / "acme" / "audit.db")

    code, report = _run_verifier(data_root)
    assert code == 1
    assert report["chains_total"] == 2
    assert report["chains_failed"] == 1
    by_label = {r["label"]: r for r in report["results"]}
    assert by_label["global"]["ok"] is True
    assert by_label["tenant:acme"]["ok"] is False


def test_concurrent_appends_never_fork_the_chain(tmp_path):
    """Regression: prev_hash was read BEFORE the write lock, so parallel
    writers chained to the same parent and verify() cried tampering. Hit in
    production within 15 min of first login (dashboard = 3 audited requests
    in parallel every 30 s). Each thread uses its own connection, like the
    API's threadpool does."""
    import threading

    db_path = tmp_path / "audit.db"
    _init_audit_db(db_path)

    n_threads, per_thread = 8, 25
    errors: list[BaseException] = []
    start = threading.Barrier(n_threads)

    def writer(t: int) -> None:
        conn = connect(db_path)         # exactly what production opens
        try:
            start.wait()
            for i in range(per_thread):
                audit.append(conn, audit.AuditEntry(
                    actor=f"operator:{t}", actor_kind="human",
                    action="tickets.list", target_kind="ticket",
                    target_id=f"{t}-{i}",
                    client_slug="global", after_state={"i": i},
                ))
        except BaseException as exc:  # noqa: BLE001 — surfaced below
            errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors, errors

    conn = connect(db_path, read_only=True)
    try:
        ok, count, first_error = audit.verify(conn)
        ts = [r[0] for r in conn.execute("SELECT ts FROM audit_log ORDER BY id")]
    finally:
        conn.close()
    assert count == n_threads * per_thread
    assert ok, first_error
    assert ts == sorted(ts)                     # timestamps monotonic with ids

