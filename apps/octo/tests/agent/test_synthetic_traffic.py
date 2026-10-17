"""Tests for the dev-only synthetic traffic generator (Task #119f)."""
from __future__ import annotations

import os
import random
import sqlite3
from pathlib import Path

import pytest

from apps.octo.auth import bootstrap
from apps.octo.dev import synthetic_traffic as st
from apps.octo.tests.auth.test_search_events import (
    _apply_events_db_migration,
    _register_client,
)


@pytest.fixture
def dev_data_root(monkeypatch, tmp_path):
    """The dev pair's own layout, ~/.octo-dev/data (HOME a throwaway dir), so
    the strict dev-root check (apps.octo.dev.dev_root) passes wherever
    pytest's tmp dir lives."""
    from cryptography.fernet import Fernet

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    root = home / ".octo-dev" / "data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    pepper = secrets_dir / "pepper.env"
    pepper.write_text("PEPPER_VERSION=pepper_v1\nPEPPER_HEX=" + "ab" * 32 + "\n")
    os.chmod(pepper, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(pepper))
    mfa = secrets_dir / "mfa-key.env"
    mfa.write_text(f"MFA_KEY_VERSION=v1\nMFA_KEY_BASE64={Fernet.generate_key().decode()}\n")
    os.chmod(mfa, 0o400)
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(mfa))
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "1")
    info = bootstrap.init_data_root()
    yield Path(info["data_root"])


def _make_production_location(root: Path, tmp_path: Path, monkeypatch) -> None:
    """Make `root` the single-host production data root, ~/octo, for the
    strict dev-root check: HOME is a throwaway dir whose `octo` points at it.
    (A plain tmp dir cannot stand in for "not a dev root": the check accepts
    any directory strictly under /tmp, as provision_setup_preview does.)"""
    home = tmp_path / "home"
    home.mkdir()
    (home / "octo").symlink_to(root, target_is_directory=True)
    monkeypatch.setenv("HOME", str(home))


def _event_count(client_dir: Path) -> int:
    conn = sqlite3.connect(client_dir / "events.db")
    try:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()


def test_synthetic_allowed_requires_env_and_dev_root(dev_data_root, monkeypatch):
    assert st.synthetic_allowed() is True  # env=1 + dev root
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "0")
    assert st.synthetic_allowed() is False  # env off


def test_synthetic_disallowed_on_non_dev_root(triage_data_root, tmp_path, monkeypatch):
    _make_production_location(triage_data_root, tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_DEV_SYNTHETIC", "1")
    assert st.synthetic_allowed() is False


def test_emit_batch_refuses_non_dev_root(triage_data_root, tmp_path, monkeypatch):
    _make_production_location(triage_data_root, tmp_path, monkeypatch)
    _register_client("acme")
    _apply_events_db_migration(triage_data_root / "clients" / "acme")
    with pytest.raises(RuntimeError, match="non-dev data root"):
        st.emit_batch(random.Random(1), n=3)


def test_emit_batch_writes_events(dev_data_root):
    _register_client("acme")
    cdir = dev_data_root / "clients" / "acme"
    _apply_events_db_migration(cdir)
    before = _event_count(cdir)
    emitted = st.emit_batch(random.Random(7), n=10)
    assert emitted == 10
    assert _event_count(cdir) == before + 10
    # The ingest sink persists payload (not summary), and our synthetic
    # payloads carry a "synthetic": true marker.
    conn = sqlite3.connect(cdir / "events.db")
    try:
        n_synth = conn.execute(
            "SELECT COUNT(*) FROM events WHERE payload LIKE '%\"synthetic\":true%'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert n_synth == 10


def test_generator_status_and_toggle():
    gen = st.SyntheticTrafficGenerator(interval_seconds=10)
    s = gen.status()
    assert s["enabled"] is False
    assert s["emitted_total"] == 0
    assert s["interval_seconds"] == 10
    gen.set_enabled(True)
    assert gen.status()["enabled"] is True
    gen.set_enabled(False)
    assert gen.status()["enabled"] is False


def test_weighted_severity_stays_in_range():
    rng = random.Random(3)
    seen = {st._weighted_severity(rng) for _ in range(500)}
    assert seen <= {"info", "low", "medium", "high", "critical"}


def test_scenarios_use_only_safe_indicators():
    # Every curated scenario's indicator must be RFC-safe (fake): TEST-NET
    # IPs, .example/.test/.invalid domains, or an obviously-fake hash.
    for sc in st._SCENARIOS:
        ind, kind = sc["indicator"], sc["indicator_type"]
        if ind is None:
            continue
        if kind == "ip":
            assert ind.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
        elif kind == "domain":
            assert ind.endswith((".example", ".test", ".invalid"))
        elif kind == "sha256":
            assert len(ind) == 64  # fake but well-formed


def test_emit_produces_scenarios_with_threat_indicators():
    # Across a batch, scenario events appear (threat summaries + indicators).
    rng = random.Random(11)
    sources_and_events = [st._make_event(rng, seq=i) for i in range(60)]
    summaries = [ev.summary for _, ev in sources_and_events]
    # At least some carry a real scenario summary (not the generic baseline).
    assert any("C2" in s or "phishing" in s or "Malware" in s or "Tor" in s
               or "Ransomware" in s or "PowerShell" in s for s in summaries)
    # And at least one carries a sketchy .example domain indicator.
    assert any(ev.indicator and ev.indicator.endswith(".example")
               for _, ev in sources_and_events)
