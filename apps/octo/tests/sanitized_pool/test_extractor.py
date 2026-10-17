"""Tests for the pool extractor (apps/octo/sanitized_pool/extractor.py).

Coverage:
  - is_enabled() default-false / opt-in / malformed safe-default
  - extract_candidates_from_payload() shape parsing + defenses
  - write_candidate(): accepted-new, accepted-update-dedup,
    accepted-update-add-tenant, rejected, YARA-rejected
  - Cursor load/save round-trip
  - run_extraction_for_tenant(): disabled returns disabled,
    happy path advances cursor, malformed events.db error path,
    audit dual-write happens for both patterns and rejects
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from apps.octo.sanitized_pool import extractor, identity, shapes


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _hmac_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Provision a per-test HMAC secret so identity.tenant_hmac()
    works without depending on real bundle secret state."""
    secret_path = tmp_path / "secrets" / "sanitized-pool-hmac.env"
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    import base64
    import secrets as _secrets
    raw = _secrets.token_bytes(32)
    text = (
        "SANITIZED_POOL_HMAC_VERSION=v1\n"
        f"SANITIZED_POOL_HMAC_BASE64={base64.urlsafe_b64encode(raw).decode()}\n"
    )
    secret_path.write_text(text)
    secret_path.chmod(0o600)
    monkeypatch.setenv("OCTO_SANITIZED_POOL_HMAC_PATH", str(secret_path))
    identity.reset_cache()
    yield
    identity.reset_cache()


def _init_audit_db(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
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
    conn.commit()
    conn.close()


def _init_registry_db(p: Path, *, extractor_enabled: bool = False) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS bundle_config (
            key             TEXT PRIMARY KEY,
            value_json      TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            updated_at      TEXT NOT NULL,
            updated_by      INTEGER
        );
    """)
    if extractor_enabled:
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) "
            "VALUES (?, ?, ?)",
            (
                extractor.EXTRACTOR_ENABLED_KEY,
                json.dumps(True),
                "2026-05-21T00:00:00Z",
            ),
        )
    conn.commit()
    conn.close()


def _init_patterns_db(p: Path) -> None:
    """Apply migrations 003 + 023 + 024 to set up patterns.db."""
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    repo_root = Path(__file__).resolve().parents[4]
    mig_dir = repo_root / "apps" / "octo" / "migrations"
    for name, target_marker in [
        ("003-initialize-patterns.sql", "-- @target: patterns"),
        ("023-sanitized-pool-hmac.sql", "-- @target: patterns"),
        ("024-pool-extractor-cursor.sql", "-- @target: patterns"),
    ]:
        sql_path = mig_dir / name
        sql = sql_path.read_text()
        # Apply only the patterns-targeted section. Splitting on the
        # next @target marker keeps audit-targeted SQL out.
        section = _section_for_target(sql, "patterns")
        conn.executescript(section)
    conn.commit()
    conn.close()


def _init_events_db(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            source         TEXT NOT NULL DEFAULT 'test',
            event_type     TEXT NOT NULL DEFAULT 'test',
            severity       TEXT NOT NULL DEFAULT 'info'
                             CHECK (severity IN ('info','low','medium','high','critical')),
            payload        TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL DEFAULT '',
            relay_status   TEXT NOT NULL DEFAULT 'pending'
                             CHECK (relay_status IN ('pending','sent','failed','skipped')),
            relay_attempts INTEGER NOT NULL DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


def _section_for_target(sql: str, target: str) -> str:
    """Extract a single @target section from a migration file.

    Migrations use `-- @target: <name>` directives to scope DDL to a
    specific DB; this helper pulls just the section we want so tests
    can apply migrations file-by-file against the right DB.
    """
    marker = f"-- @target: {target}"
    parts = sql.split("-- @target:")
    out_lines: list[str] = []
    # Always include any header (pragma + comments) before the first
    # @target marker.
    if parts and not parts[0].lstrip().startswith(target):
        out_lines.append(parts[0])
    for chunk in parts[1:]:
        head, _, rest = chunk.partition("\n")
        if head.strip() == target:
            out_lines.append(rest)
    return "\n".join(out_lines)


def _seed_event(events_conn: sqlite3.Connection, payload: dict) -> int:
    cur = events_conn.execute(
        "INSERT INTO events (payload, payload_sha256) VALUES (?, ?)",
        (json.dumps(payload), "x"),
    )
    events_conn.commit()
    return int(cur.lastrowid)


def _connect_row(p: Path) -> sqlite3.Connection:
    """sqlite3.connect with Row factory + foreign keys — matches the
    apps.octo.db.connect() shape that audit.append() relies on."""
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _full_environment(tmp_path: Path, *, extractor_enabled: bool):
    """Wire up the full set of DBs for an end-to-end test."""
    registry = tmp_path / "registry.db"
    patterns = tmp_path / "global" / "patterns.db"
    global_audit = tmp_path / "global" / "audit.db"
    events = tmp_path / "clients" / "acme" / "events.db"
    tenant_audit = tmp_path / "clients" / "acme" / "audit.db"
    _init_registry_db(registry, extractor_enabled=extractor_enabled)
    _init_patterns_db(patterns)
    _init_audit_db(global_audit)
    _init_events_db(events)
    _init_audit_db(tenant_audit)
    return {
        "registry": registry,
        "patterns": patterns,
        "global_audit": global_audit,
        "events": events,
        "tenant_audit": tenant_audit,
    }


# ---------------------------------------------------------------------------
# is_enabled
# ---------------------------------------------------------------------------

class TestIsEnabled:
    def test_no_bundle_config_table_returns_false(self, tmp_path: Path) -> None:
        p = tmp_path / "registry.db"
        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        assert extractor.is_enabled(conn) is False

    def test_no_row_returns_false(self, tmp_path: Path) -> None:
        p = tmp_path / "registry.db"
        _init_registry_db(p, extractor_enabled=False)
        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        assert extractor.is_enabled(conn) is False

    def test_explicit_true_returns_true(self, tmp_path: Path) -> None:
        p = tmp_path / "registry.db"
        _init_registry_db(p, extractor_enabled=True)
        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        assert extractor.is_enabled(conn) is True

    def test_explicit_false_returns_false(self, tmp_path: Path) -> None:
        p = tmp_path / "registry.db"
        _init_registry_db(p, extractor_enabled=False)
        conn = sqlite3.connect(str(p))
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) VALUES (?, ?, ?)",
            (extractor.EXTRACTOR_ENABLED_KEY, "false", "2026-05-21"),
        )
        conn.commit()
        conn.row_factory = sqlite3.Row
        assert extractor.is_enabled(conn) is False

    def test_malformed_value_returns_false(self, tmp_path: Path) -> None:
        p = tmp_path / "registry.db"
        _init_registry_db(p, extractor_enabled=False)
        conn = sqlite3.connect(str(p))
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) VALUES (?, ?, ?)",
            (extractor.EXTRACTOR_ENABLED_KEY, "{garbage", "2026-05-21"),
        )
        conn.commit()
        conn.row_factory = sqlite3.Row
        # Config error must NEVER accidentally enable extraction.
        assert extractor.is_enabled(conn) is False

    def test_non_bool_value_returns_false(self, tmp_path: Path) -> None:
        p = tmp_path / "registry.db"
        _init_registry_db(p, extractor_enabled=False)
        conn = sqlite3.connect(str(p))
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) VALUES (?, ?, ?)",
            (extractor.EXTRACTOR_ENABLED_KEY, json.dumps("yes"), "2026-05-21"),
        )
        conn.commit()
        conn.row_factory = sqlite3.Row
        assert extractor.is_enabled(conn) is False


# ---------------------------------------------------------------------------
# extract_candidates_from_payload
# ---------------------------------------------------------------------------

class TestExtractCandidates:
    def test_extracts_iocs_field(self) -> None:
        payload = {
            "iocs": [
                {"type": "domain", "value": "evil.example"},
                {"type": "ip", "value": "8.8.8.8"},
            ],
        }
        cands = extractor.extract_candidates_from_payload(payload, source_event_id=42)
        assert len(cands) == 2
        assert cands[0].kind == "domain"
        assert cands[0].value == "evil.example"
        assert cands[0].source_event_id == 42
        assert cands[1].kind == "ip"

    def test_preserves_subkind(self) -> None:
        payload = {
            "iocs": [
                {"type": "file_hash", "value": "a" * 32, "subkind": "md5"},
            ],
        }
        cands = extractor.extract_candidates_from_payload(payload)
        assert cands[0].subkind == "md5"

    def test_non_dict_payload_returns_empty(self) -> None:
        assert extractor.extract_candidates_from_payload(None) == []
        assert extractor.extract_candidates_from_payload("string") == []
        assert extractor.extract_candidates_from_payload([1, 2, 3]) == []

    def test_missing_iocs_field_returns_empty(self) -> None:
        assert extractor.extract_candidates_from_payload({"x": 1}) == []

    def test_iocs_not_a_list_returns_empty(self) -> None:
        assert extractor.extract_candidates_from_payload({"iocs": "not-a-list"}) == []
        assert extractor.extract_candidates_from_payload({"iocs": {"a": 1}}) == []

    def test_individual_malformed_candidates_skipped(self) -> None:
        payload = {
            "iocs": [
                {"type": "domain", "value": "ok.example"},
                "not-a-dict",
                {"type": "domain"},  # missing value
                {"value": "no-type"},  # missing type
                {"type": 123, "value": "non-string-type"},
                {"type": "domain", "value": 999},  # non-string value
                {"type": "ip", "value": "1.1.1.1"},
            ],
        }
        cands = extractor.extract_candidates_from_payload(payload)
        # Only the two well-formed entries make it through.
        assert [c.value for c in cands] == ["ok.example", "1.1.1.1"]

    def test_non_string_subkind_dropped_to_none(self) -> None:
        payload = {
            "iocs": [
                {"type": "file_hash", "value": "x", "subkind": 12},
            ],
        }
        cands = extractor.extract_candidates_from_payload(payload)
        assert cands[0].subkind is None


# ---------------------------------------------------------------------------
# write_candidate — accepted path
# ---------------------------------------------------------------------------

class TestWriteCandidateAccepted:
    def _conns(self, tmp_path: Path):
        env = _full_environment(tmp_path, extractor_enabled=True)
        return (
            _connect_row(env["patterns"]),
            _connect_row(env["global_audit"]),
            _connect_row(env["tenant_audit"]),
        )

    def test_new_pattern_inserts_with_tenant_hmac(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(
            kind="domain", value="evil.example", source_event_id=1,
        )
        outcome = extractor.write_candidate(
            cand, "acme", p_conn, ga_conn, ta_conn,
        )
        assert outcome.kind == "pattern_new"
        assert outcome.pattern_id is not None

        row = p_conn.execute(
            "SELECT ioc_type, ioc_value, tenant_hmacs, client_count, "
            "hmac_version, pepper_version FROM patterns"
        ).fetchone()
        assert row["ioc_type"] == "domain"
        assert row["ioc_value"] == "evil.example"
        hmacs = json.loads(row["tenant_hmacs"])
        assert len(hmacs) == 1
        assert hmacs[0] == identity.tenant_hmac("acme")
        assert row["client_count"] == 1
        assert row["hmac_version"] == "v1"
        # Legacy column gets the deprecation sentinel.
        assert row["pepper_version"] == "deprecated"

    def test_audit_chains_both_get_row(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(
            kind="domain", value="evil.example", source_event_id=1,
        )
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)

        g_count = ga_conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'pool_pattern_added'"
        ).fetchone()[0]
        t_count = ta_conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'pool_pattern_added'"
        ).fetchone()[0]
        assert g_count == 1
        assert t_count == 1

    def test_audit_after_state_carries_tenant_hmac_not_slug(
        self, tmp_path: Path,
    ) -> None:
        """The audit row's after_state should record the HMAC for
        cross-tenant joins. The slug remains in client_slug (audit
        is internal-bundle context per the M4 module docstring)."""
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(kind="domain", value="evil.example")
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)

        row = ga_conn.execute(
            "SELECT after_state, client_slug FROM audit_log "
            "WHERE action = 'pool_pattern_added'"
        ).fetchone()
        after = json.loads(row[0])
        assert after["tenant_hmac"] == identity.tenant_hmac("acme")
        # client_slug is the legitimate slug record (M4 keeps it).
        assert row[1] == "acme"

    def test_existing_pattern_same_tenant_dedups(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(kind="domain", value="evil.example")
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)
        # Same tenant submits same IOC again — should NOT bump count.
        outcome2 = extractor.write_candidate(
            cand, "acme", p_conn, ga_conn, ta_conn,
        )
        assert outcome2.kind == "skipped_duplicate"

        row = p_conn.execute(
            "SELECT tenant_hmacs, client_count FROM patterns"
        ).fetchone()
        assert json.loads(row["tenant_hmacs"]) == [identity.tenant_hmac("acme")]
        assert row["client_count"] == 1

        # And the second write does NOT create a second audit row.
        g_count = ga_conn.execute(
            "SELECT COUNT(*) FROM audit_log "
            "WHERE action IN ('pool_pattern_added', 'pool_pattern_tenant_added')"
        ).fetchone()[0]
        assert g_count == 1

    def test_existing_pattern_new_tenant_appends_hmac(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(kind="domain", value="evil.example")
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)

        # Now a DIFFERENT tenant submits the same IOC.
        # We need a tenant audit DB for the second tenant for M4.
        beta_audit = tmp_path / "clients" / "beta" / "audit.db"
        _init_audit_db(beta_audit)
        beta_audit_conn = _connect_row(beta_audit)
        outcome = extractor.write_candidate(
            cand, "beta", p_conn, ga_conn, beta_audit_conn,
        )
        assert outcome.kind == "pattern_updated"

        row = p_conn.execute(
            "SELECT tenant_hmacs, client_count FROM patterns"
        ).fetchone()
        hmacs = json.loads(row["tenant_hmacs"])
        assert len(hmacs) == 2
        assert identity.tenant_hmac("acme") in hmacs
        assert identity.tenant_hmac("beta") in hmacs
        assert row["client_count"] == 2

    def test_file_hash_md5_maps_to_md5_ioc_type(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(
            kind="file_hash", value="a" * 32, subkind="md5",
        )
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)
        row = p_conn.execute(
            "SELECT ioc_type FROM patterns"
        ).fetchone()
        assert row["ioc_type"] == "md5"

    def test_ipv6_maps_to_ipv6_ioc_type(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        # Public IPv6 (Cloudflare DNS) — avoid 2001:db8::/32 which is
        # in the RFC3849 documentation range and rejected as reserved.
        cand = extractor.Candidate(kind="ip", value="2606:4700:4700::1111")
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)
        row = p_conn.execute("SELECT ioc_type FROM patterns").fetchone()
        assert row["ioc_type"] == "ipv6"


# ---------------------------------------------------------------------------
# write_candidate — rejected path
# ---------------------------------------------------------------------------

class TestWriteCandidateRejected:
    def _conns(self, tmp_path: Path):
        env = _full_environment(tmp_path, extractor_enabled=True)
        return (
            _connect_row(env["patterns"]),
            _connect_row(env["global_audit"]),
            _connect_row(env["tenant_audit"]),
        )

    def test_yara_candidate_goes_to_rejects_with_hmac(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(kind="yara", value="rule R {strings: ...}")
        outcome = extractor.write_candidate(
            cand, "acme", p_conn, ga_conn, ta_conn,
        )
        assert outcome.kind == "reject"

        row = p_conn.execute(
            "SELECT source_tenant_hmac, source_slug, reason_code, hmac_version "
            "FROM sanitization_rejects"
        ).fetchone()
        # M3 invariant: real slug NEVER lands in source_slug.
        assert row["source_slug"] == "<hmac>"
        assert row["source_tenant_hmac"] == identity.tenant_hmac("acme")
        assert row["reason_code"] == shapes.REASON_YARA_DEFERRED
        assert row["hmac_version"] == "v1"

    def test_reject_writes_no_pattern_row(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(kind="ip", value="192.0.2.1")  # reserved (documentation)
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)
        n = p_conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        assert n == 0

    def test_reject_writes_audit_row_to_both_chains(self, tmp_path: Path) -> None:
        p_conn, ga_conn, ta_conn = self._conns(tmp_path)
        cand = extractor.Candidate(kind="domain", value="no-tld-here")
        extractor.write_candidate(cand, "acme", p_conn, ga_conn, ta_conn)

        g = ga_conn.execute(
            "SELECT COUNT(*) FROM audit_log "
            "WHERE action = 'pool_candidate_rejected'"
        ).fetchone()[0]
        t = ta_conn.execute(
            "SELECT COUNT(*) FROM audit_log "
            "WHERE action = 'pool_candidate_rejected'"
        ).fetchone()[0]
        assert g == 1
        assert t == 1


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------

class TestCursor:
    def test_load_returns_zero_when_no_row(self, tmp_path: Path) -> None:
        env = _full_environment(tmp_path, extractor_enabled=False)
        conn = sqlite3.connect(str(env["patterns"]))
        conn.row_factory = sqlite3.Row
        assert extractor._load_cursor(conn, "acme") == 0

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        env = _full_environment(tmp_path, extractor_enabled=False)
        conn = sqlite3.connect(str(env["patterns"]))
        conn.row_factory = sqlite3.Row
        extractor._save_cursor(
            conn, "acme",
            last_event_id=42, status="ok", error=None,
            events_seen_delta=10, patterns_delta=3, rejects_delta=1,
            now="2026-05-21T00:00:00.000Z",
        )
        conn.commit()
        assert extractor._load_cursor(conn, "acme") == 42

    def test_save_accumulates_deltas(self, tmp_path: Path) -> None:
        env = _full_environment(tmp_path, extractor_enabled=False)
        conn = sqlite3.connect(str(env["patterns"]))
        conn.row_factory = sqlite3.Row
        extractor._save_cursor(
            conn, "acme", last_event_id=10, status="ok", error=None,
            events_seen_delta=5, patterns_delta=2, rejects_delta=1,
            now="2026-05-21T00:00:00.000Z",
        )
        extractor._save_cursor(
            conn, "acme", last_event_id=20, status="ok", error=None,
            events_seen_delta=7, patterns_delta=3, rejects_delta=0,
            now="2026-05-21T00:00:00.000Z",
        )
        conn.commit()
        row = conn.execute(
            "SELECT events_seen_total, patterns_written, rejects_written "
            "FROM pool_extractor_cursor WHERE tenant_slug = ?",
            ("acme",),
        ).fetchone()
        assert row["events_seen_total"] == 12
        assert row["patterns_written"] == 5
        assert row["rejects_written"] == 1


# ---------------------------------------------------------------------------
# run_extraction_for_tenant
# ---------------------------------------------------------------------------

class TestRunExtractionForTenant:
    def _open_all(self, env: dict[str, Path]):
        from apps.octo.db import connect
        return {
            "registry": connect(env["registry"], read_only=True),
            "events": connect(env["events"], read_only=True),
            "patterns": connect(env["patterns"]),
            "global_audit": connect(env["global_audit"]),
            "tenant_audit": connect(env["tenant_audit"]),
        }

    def test_disabled_returns_disabled_no_writes(self, tmp_path: Path) -> None:
        env = _full_environment(tmp_path, extractor_enabled=False)
        conns = self._open_all(env)
        try:
            _seed_event(sqlite3.connect(str(env["events"])), {
                "iocs": [{"type": "domain", "value": "evil.example"}],
            })
            stats = extractor.run_extraction_for_tenant(
                "acme",
                registry_conn=conns["registry"],
                events_conn=conns["events"],
                patterns_conn=conns["patterns"],
                global_audit_conn=conns["global_audit"],
                tenant_audit_conn=conns["tenant_audit"],
            )
        finally:
            for c in conns.values():
                c.close()
        assert stats.status == "disabled"
        # No pattern was written.
        pc = sqlite3.connect(str(env["patterns"]))
        try:
            n = pc.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        finally:
            pc.close()
        assert n == 0

    def test_happy_path_advances_cursor(self, tmp_path: Path) -> None:
        env = _full_environment(tmp_path, extractor_enabled=True)
        ev_conn = sqlite3.connect(str(env["events"]))
        try:
            ev1 = _seed_event(ev_conn, {
                "iocs": [{"type": "domain", "value": "evil-1.example"}],
            })
            ev2 = _seed_event(ev_conn, {
                "iocs": [{"type": "domain", "value": "evil-2.example"}],
            })
            ev3 = _seed_event(ev_conn, {
                "iocs": [
                    {"type": "ip", "value": "8.8.8.8"},
                    {"type": "yara", "value": "rule R{}"},
                ],
            })
        finally:
            ev_conn.close()

        conns = self._open_all(env)
        try:
            stats = extractor.run_extraction_for_tenant(
                "acme",
                registry_conn=conns["registry"],
                events_conn=conns["events"],
                patterns_conn=conns["patterns"],
                global_audit_conn=conns["global_audit"],
                tenant_audit_conn=conns["tenant_audit"],
            )
        finally:
            for c in conns.values():
                c.close()

        assert stats.status == "ok"
        assert stats.events_scanned == 3
        assert stats.candidates_seen == 4
        assert stats.patterns_written == 3
        assert stats.rejects_written == 1
        assert stats.advanced_cursor_to == ev3

        # Second run with no new events → no-op.
        conns = self._open_all(env)
        try:
            stats2 = extractor.run_extraction_for_tenant(
                "acme",
                registry_conn=conns["registry"],
                events_conn=conns["events"],
                patterns_conn=conns["patterns"],
                global_audit_conn=conns["global_audit"],
                tenant_audit_conn=conns["tenant_audit"],
            )
        finally:
            for c in conns.values():
                c.close()
        assert stats2.status == "ok"
        assert stats2.events_scanned == 0
        assert stats2.advanced_cursor_to == ev3

    def test_a_restricted_domain_never_feeds_the_pool(self, tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
        """Rule B7 (CSAM, v0.17.1): an event naming a domain the tenant holds
        as restricted evidence is never mined — and an unreadable list
        extracts nothing (the cursor stays). Placeholder domain only."""
        from apps.octo.threat import restricted

        monkeypatch.setattr(restricted, "restricted_domains",
                            lambda slug: {"csam-placeholder.example.test"})
        env = _full_environment(tmp_path, extractor_enabled=True)
        ev_conn = sqlite3.connect(str(env["events"]))
        try:
            _seed_event(ev_conn, {"iocs": [
                {"type": "domain", "value": "img.csam-placeholder.example.test"}]})
            good = _seed_event(ev_conn, {"iocs": [{"type": "domain",
                                                   "value": "evil-3.example"}]})
        finally:
            ev_conn.close()
        conns = self._open_all(env)
        try:
            stats = extractor.run_extraction_for_tenant(
                "acme", registry_conn=conns["registry"], events_conn=conns["events"],
                patterns_conn=conns["patterns"], global_audit_conn=conns["global_audit"],
                tenant_audit_conn=conns["tenant_audit"])
            values = [r[0] for r in conns["patterns"].execute(
                "SELECT ioc_value FROM patterns").fetchall()]
        finally:
            for c in conns.values():
                c.close()
        assert stats.status == "ok" and stats.events_scanned == 2
        assert stats.patterns_written == 1 and stats.advanced_cursor_to == good
        assert not any("csam-placeholder" in str(v) for v in values)

        def unreadable(slug):
            raise sqlite3.OperationalError("locked")

        monkeypatch.setattr(restricted, "restricted_domains", unreadable)
        ev_conn = sqlite3.connect(str(env["events"]))
        try:
            _seed_event(ev_conn, {"iocs": [{"type": "domain", "value": "evil-4.example"}]})
        finally:
            ev_conn.close()
        conns = self._open_all(env)
        try:
            stats = extractor.run_extraction_for_tenant(
                "acme", registry_conn=conns["registry"], events_conn=conns["events"],
                patterns_conn=conns["patterns"], global_audit_conn=conns["global_audit"],
                tenant_audit_conn=conns["tenant_audit"])
        finally:
            for c in conns.values():
                c.close()
        assert stats.status == "error" and stats.patterns_written == 0

    def test_malformed_payload_does_not_crash(self, tmp_path: Path) -> None:
        env = _full_environment(tmp_path, extractor_enabled=True)
        ev_conn = sqlite3.connect(str(env["events"]))
        try:
            ev_conn.execute(
                "INSERT INTO events (payload, payload_sha256) VALUES (?, ?)",
                ("not-json", "x"),
            )
            ev_conn.commit()
        finally:
            ev_conn.close()

        conns = self._open_all(env)
        try:
            stats = extractor.run_extraction_for_tenant(
                "acme",
                registry_conn=conns["registry"],
                events_conn=conns["events"],
                patterns_conn=conns["patterns"],
                global_audit_conn=conns["global_audit"],
                tenant_audit_conn=conns["tenant_audit"],
            )
        finally:
            for c in conns.values():
                c.close()
        assert stats.status == "ok"
        assert stats.events_scanned == 1
        assert stats.candidates_seen == 0

    def test_max_events_caps_run(self, tmp_path: Path) -> None:
        env = _full_environment(tmp_path, extractor_enabled=True)
        ev_conn = sqlite3.connect(str(env["events"]))
        try:
            for i in range(10):
                _seed_event(ev_conn, {
                    "iocs": [{"type": "domain", "value": f"evil-{i}.example"}],
                })
        finally:
            ev_conn.close()

        conns = self._open_all(env)
        try:
            stats = extractor.run_extraction_for_tenant(
                "acme",
                registry_conn=conns["registry"],
                events_conn=conns["events"],
                patterns_conn=conns["patterns"],
                global_audit_conn=conns["global_audit"],
                tenant_audit_conn=conns["tenant_audit"],
                max_events=3,
            )
        finally:
            for c in conns.values():
                c.close()
        assert stats.events_scanned == 3
        # Cursor is at event 3; next run picks up at 4.
        assert stats.advanced_cursor_to == 3
