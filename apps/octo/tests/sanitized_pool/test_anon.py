"""Tests for sanitized_pool.anon (M6 k-anonymity read-side filter).

Coverage:
  - passes_k_anonymity() boundary behavior
  - filter_rows() drops below-k rows, keeps at-k and above
  - compute_distinct_tenant_count() handles NULL / empty / malformed
  - load_k_threshold() reads from bundle_config + falls back safely
  - default k=3
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from apps.octo.sanitized_pool import anon


# ---------------------------------------------------------------------------
# passes_k_anonymity
# ---------------------------------------------------------------------------

class TestPassesKAnonymity:
    def test_below_threshold_fails(self) -> None:
        assert anon.passes_k_anonymity(2, k=3) is False

    def test_at_threshold_passes(self) -> None:
        assert anon.passes_k_anonymity(3, k=3) is True

    def test_above_threshold_passes(self) -> None:
        assert anon.passes_k_anonymity(100, k=3) is True

    def test_zero_count_fails(self) -> None:
        assert anon.passes_k_anonymity(0, k=1) is False
        assert anon.passes_k_anonymity(0, k=3) is False

    def test_k_zero_rejected(self) -> None:
        with pytest.raises(ValueError, match="k must be >= 1"):
            anon.passes_k_anonymity(5, k=0)

    def test_k_negative_rejected(self) -> None:
        with pytest.raises(ValueError):
            anon.passes_k_anonymity(5, k=-1)


# ---------------------------------------------------------------------------
# filter_rows
# ---------------------------------------------------------------------------

class TestFilterRows:
    def test_filters_below_threshold(self) -> None:
        rows = [
            {"ioc": "a", "distinct_tenant_count": 2},
            {"ioc": "b", "distinct_tenant_count": 3},
            {"ioc": "c", "distinct_tenant_count": 4},
        ]
        out = anon.filter_rows(rows, k=3)
        iocs = [r["ioc"] for r in out]
        assert iocs == ["b", "c"]

    def test_empty_input(self) -> None:
        assert anon.filter_rows([], k=3) == []

    def test_missing_count_field_treated_as_zero(self) -> None:
        rows = [{"ioc": "x"}, {"ioc": "y", "distinct_tenant_count": 5}]
        out = anon.filter_rows(rows, k=1)
        # The row missing the count field is dropped.
        assert [r["ioc"] for r in out] == ["y"]

    def test_malformed_count_field_dropped(self) -> None:
        """A non-integer count value is treated as below-threshold (safe
        default)."""
        rows = [
            {"ioc": "bad", "distinct_tenant_count": "five"},
            {"ioc": "good", "distinct_tenant_count": 5},
        ]
        out = anon.filter_rows(rows, k=3)
        assert [r["ioc"] for r in out] == ["good"]

    def test_custom_count_field(self) -> None:
        rows = [
            {"ioc": "a", "n_tenants": 1},
            {"ioc": "b", "n_tenants": 3},
        ]
        out = anon.filter_rows(rows, k=3, count_field="n_tenants")
        assert [r["ioc"] for r in out] == ["b"]


# ---------------------------------------------------------------------------
# compute_distinct_tenant_count
# ---------------------------------------------------------------------------

class TestComputeDistinctTenantCount:
    def test_normal(self) -> None:
        v = json.dumps(["a" * 64, "b" * 64, "c" * 64])
        assert anon.compute_distinct_tenant_count(v) == 3

    def test_dedupes(self) -> None:
        v = json.dumps(["a" * 64, "a" * 64, "b" * 64])
        assert anon.compute_distinct_tenant_count(v) == 2

    def test_null_returns_zero(self) -> None:
        assert anon.compute_distinct_tenant_count(None) == 0

    def test_empty_string_returns_zero(self) -> None:
        assert anon.compute_distinct_tenant_count("") == 0

    def test_empty_array_returns_zero(self) -> None:
        assert anon.compute_distinct_tenant_count("[]") == 0

    def test_malformed_json_returns_zero(self) -> None:
        assert anon.compute_distinct_tenant_count("{not json") == 0

    def test_non_array_json_returns_zero(self) -> None:
        # An attacker who managed to write a non-array value shouldn't
        # crash the read path.
        assert anon.compute_distinct_tenant_count('"single-string"') == 0
        assert anon.compute_distinct_tenant_count("{}") == 0
        assert anon.compute_distinct_tenant_count("12345") == 0


# ---------------------------------------------------------------------------
# load_k_threshold (bundle_config integration)
# ---------------------------------------------------------------------------

class TestLoadKThreshold:
    def _mk_registry_with_bundle_config(self, tmp_path: Path) -> sqlite3.Connection:
        """Create a minimal registry.db with the bundle_config table."""
        p = tmp_path / "registry.db"
        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        conn.executescript("""
            CREATE TABLE bundle_config (
                key             TEXT PRIMARY KEY,
                value_json      TEXT NOT NULL,
                description     TEXT NOT NULL DEFAULT '',
                updated_at      TEXT NOT NULL,
                updated_by      INTEGER
            );
        """)
        return conn

    def test_default_when_no_bundle_config_table(self, tmp_path: Path) -> None:
        """Pre-migration-022 case — no bundle_config table at all."""
        p = tmp_path / "registry.db"
        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        # No table created.
        cfg = anon.load_k_threshold(conn)
        assert cfg.k == anon.DEFAULT_K
        assert cfg.source == "default"

    def test_default_when_no_row(self, tmp_path: Path) -> None:
        conn = self._mk_registry_with_bundle_config(tmp_path)
        cfg = anon.load_k_threshold(conn)
        assert cfg.k == anon.DEFAULT_K
        assert cfg.source == "default"

    def test_override_via_bundle_config(self, tmp_path: Path) -> None:
        conn = self._mk_registry_with_bundle_config(tmp_path)
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) VALUES (?, ?, ?)",
            (anon.BUNDLE_CONFIG_KEY, json.dumps({"k": 5}), "2026-05-21T00:00:00Z"),
        )
        conn.commit()
        cfg = anon.load_k_threshold(conn)
        assert cfg.k == 5
        assert cfg.source == "bundle_config"

    def test_malformed_value_falls_back_to_default(self, tmp_path: Path) -> None:
        """Operator typo / corrupted value shouldn't accidentally weaken
        privacy. Fall back to default."""
        conn = self._mk_registry_with_bundle_config(tmp_path)
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) VALUES (?, ?, ?)",
            (anon.BUNDLE_CONFIG_KEY, "{not json", "2026-05-21T00:00:00Z"),
        )
        conn.commit()
        cfg = anon.load_k_threshold(conn)
        assert cfg.k == anon.DEFAULT_K
        assert cfg.source == "default"

    def test_value_zero_falls_back_to_default(self, tmp_path: Path) -> None:
        """k=0 would defeat the control entirely. Reject + fall back."""
        conn = self._mk_registry_with_bundle_config(tmp_path)
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) VALUES (?, ?, ?)",
            (anon.BUNDLE_CONFIG_KEY, json.dumps({"k": 0}), "2026-05-21T00:00:00Z"),
        )
        conn.commit()
        cfg = anon.load_k_threshold(conn)
        assert cfg.k == anon.DEFAULT_K

    def test_value_non_int_falls_back_to_default(self, tmp_path: Path) -> None:
        conn = self._mk_registry_with_bundle_config(tmp_path)
        conn.execute(
            "INSERT INTO bundle_config (key, value_json, updated_at) VALUES (?, ?, ?)",
            (anon.BUNDLE_CONFIG_KEY, json.dumps({"k": "three"}), "2026-05-21T00:00:00Z"),
        )
        conn.commit()
        cfg = anon.load_k_threshold(conn)
        assert cfg.k == anon.DEFAULT_K

    def test_custom_default(self, tmp_path: Path) -> None:
        """The default arg is overrideable for tests / future tuning."""
        p = tmp_path / "registry.db"
        conn = sqlite3.connect(str(p))
        # Empty DB.
        cfg = anon.load_k_threshold(conn, default=10)
        assert cfg.k == 10
        assert cfg.source == "default"


def test_default_k_is_three() -> None:
    """Sanity check that the safety envelope's default (k=3) is what
    ships."""
    assert anon.DEFAULT_K == 3
