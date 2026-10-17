"""InstanceManager + persistence helpers.

Covers:
  - create_instance round-trips through credentials vault + DB
  - list / get reflect the persisted state
  - InstanceManager.start_instance constructs the adapter, calls .start(),
    flips status to 'running', and tracks the running set
  - start_instance with unknown vendor_slug → InstanceLifecycleError +
    status='error' persisted (does NOT crash the boot loop)
  - start_all_persisted skips disabled rows + survives a broken adapter
  - stop_instance + stop_all_running drop from the running set
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from apps.octo import paths
from apps.octo.framework.registry import AdapterRegistry, InMemoryRegistryBackend
from apps.octo.instances import (
    InstanceLifecycleError,
    InstanceManager,
    create_instance,
    list_instances,
    update_instance_status,
)
from apps.octo.instances.manager import disable_instance, get_instance


# ---------------------------------------------------------------------------
# Fixtures — minimal bootstrap so we have registry.db with migration 007
# applied + the adapter credentials key in place.
# ---------------------------------------------------------------------------

@pytest.fixture
def bedrock_root(monkeypatch, tmp_path):
    from apps.octo.auth import bootstrap

    root = tmp_path / "octo-data"
    monkeypatch.setenv("OCTO_DATA_ROOT", str(root))

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    pepper_file = secrets_dir / "pepper.env"
    pepper_file.write_text(
        "PEPPER_VERSION=pepper_v1\n"
        "PEPPER_HEX=" + "ab" * 32 + "\n"
    )
    os.chmod(pepper_file, 0o400)
    monkeypatch.setenv("OCTO_PEPPER_PATH", str(pepper_file))

    mfa_file = secrets_dir / "mfa-key.env"
    mfa_file.write_text(
        "MFA_KEY_VERSION=v1\n"
        f"MFA_KEY_BASE64={Fernet.generate_key().decode()}\n"
    )
    os.chmod(mfa_file, 0o400)
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(mfa_file))

    cred_key_file = secrets_dir / "adapter-credentials-key.env"
    monkeypatch.setenv("OCTO_ADAPTER_CREDENTIALS_KEY_PATH", str(cred_key_file))

    from apps.octo.credentials import ensure_key_file
    ensure_key_file()

    bootstrap.init_data_root()
    yield Path(root)


# ---------------------------------------------------------------------------
# Stub adapter used to verify start/stop without depending on a real upstream
# ---------------------------------------------------------------------------

class _CountingAdapter:
    """Minimal SourceAdapter-shaped class for lifecycle tests.

    The InstanceManager only calls `start(config)` and `stop()`, so the
    rest of the contract surface can stay unimplemented.
    """
    vendor_slug = "stub-counter"
    starts: int = 0
    stops: int = 0
    last_config: dict[str, Any] | None = None

    def __init__(self) -> None:
        pass

    def start(self, instance_config: dict[str, Any]) -> None:
        type(self).starts += 1
        type(self).last_config = instance_config

    def stop(self) -> None:
        type(self).stops += 1


class _ExplodingAdapter:
    vendor_slug = "stub-explode"

    def start(self, instance_config: dict[str, Any]) -> None:
        raise RuntimeError("boom")

    def stop(self) -> None:
        pass


def _reset_counters() -> None:
    _CountingAdapter.starts = 0
    _CountingAdapter.stops = 0
    _CountingAdapter.last_config = None


@pytest.fixture
def registry_with_stub():
    _reset_counters()
    reg = AdapterRegistry(backend=InMemoryRegistryBackend())
    reg.register_adapter_class(_CountingAdapter)
    return reg


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def test_create_instance_round_trips_through_vault_and_db(bedrock_root):
    payload = {"WAZUH_API_KEY": "sample-key-fixture", "WAZUH_MANAGER_URL": "https://wm.test"}
    rec = create_instance(
        vendor_slug="wazuh",
        display_name="bundled-wazuh",
        credentials_dict=payload,
        instance_config={"poll_interval_sec": 30},
        default_tenant_slug="_unmapped",
        configured_by_operator_id=None,
    )
    assert rec.vendor_slug == "wazuh"
    assert rec.display_name == "bundled-wazuh"
    assert rec.status == "starting"
    assert rec.default_tenant_slug == "_unmapped"
    assert rec.configured_by_operator_id is None
    assert rec.instance_config["poll_interval_sec"] == 30

    # cred_ref is the encrypted blob — round-trip back via vault
    from apps.octo import credentials
    assert credentials.load(rec.cred_ref) == payload


def test_list_instances_returns_persisted_rows(bedrock_root):
    create_instance(
        vendor_slug="wazuh", display_name="a",
        credentials_dict={"k": "v"},
    )
    rows = list_instances()
    assert len(rows) == 1
    assert rows[0].vendor_slug == "wazuh"


def test_unique_index_blocks_double_active(bedrock_root):
    import sqlite3
    create_instance(
        vendor_slug="wazuh", display_name="a",
        credentials_dict={"k": "v"},
    )
    with pytest.raises(sqlite3.IntegrityError):
        create_instance(
            vendor_slug="wazuh", display_name="b",
            credentials_dict={"k": "v2"},
        )


def test_disable_then_create_succeeds(bedrock_root):
    """After disable, a fresh active row is allowed (partial unique index)."""
    r1 = create_instance(
        vendor_slug="wazuh", display_name="a",
        credentials_dict={"k": "v"},
    )
    disable_instance(r1.id, disabled_by_operator_id=None, reason="test")
    r2 = create_instance(
        vendor_slug="wazuh", display_name="b",
        credentials_dict={"k": "v2"},
    )
    assert r2.id != r1.id


def test_update_instance_status_writes_status_and_detail(bedrock_root):
    rec = create_instance(
        vendor_slug="wazuh", display_name="a",
        credentials_dict={"k": "v"},
    )
    update_instance_status(rec.id, status="running", status_detail="ok")
    reloaded = get_instance(rec.id)
    assert reloaded.status == "running"
    assert reloaded.status_detail == "ok"


# ---------------------------------------------------------------------------
# InstanceManager
# ---------------------------------------------------------------------------

def test_start_instance_invokes_adapter_and_marks_running(bedrock_root, registry_with_stub):
    rec = create_instance(
        vendor_slug="stub-counter", display_name="ctr",
        credentials_dict={"X": "1"},
        instance_config={"foo": "bar"},
        default_tenant_slug="acme",
    )
    mgr = InstanceManager(adapter_registry=registry_with_stub)
    mgr.start_instance(rec)

    assert _CountingAdapter.starts == 1
    # Credentials + config + default_tenant_slug merged
    assert _CountingAdapter.last_config["X"] == "1"
    assert _CountingAdapter.last_config["foo"] == "bar"
    assert _CountingAdapter.last_config["default_tenant_slug"] == "acme"

    reloaded = get_instance(rec.id)
    assert reloaded.status == "running"
    assert mgr.is_running(rec.id)


def test_start_instance_is_idempotent(bedrock_root, registry_with_stub):
    rec = create_instance(
        vendor_slug="stub-counter", display_name="ctr",
        credentials_dict={"X": "1"},
    )
    mgr = InstanceManager(adapter_registry=registry_with_stub)
    mgr.start_instance(rec)
    mgr.start_instance(rec)
    assert _CountingAdapter.starts == 1  # second call is a no-op


def test_start_instance_unknown_vendor_records_error(bedrock_root, registry_with_stub):
    rec = create_instance(
        vendor_slug="not-registered", display_name="x",
        credentials_dict={"k": "v"},
    )
    mgr = InstanceManager(adapter_registry=registry_with_stub)
    with pytest.raises(InstanceLifecycleError):
        mgr.start_instance(rec)
    reloaded = get_instance(rec.id)
    assert reloaded.status == "error"
    assert "not registered" in (reloaded.status_detail or "")


def test_start_instance_adapter_raise_records_error(bedrock_root):
    reg = AdapterRegistry(backend=InMemoryRegistryBackend())
    reg.register_adapter_class(_ExplodingAdapter)
    rec = create_instance(
        vendor_slug="stub-explode", display_name="ex",
        credentials_dict={"k": "v"},
    )
    mgr = InstanceManager(adapter_registry=reg)
    with pytest.raises(InstanceLifecycleError):
        mgr.start_instance(rec)
    reloaded = get_instance(rec.id)
    assert reloaded.status == "error"
    assert "boom" in (reloaded.status_detail or "")


def test_stop_instance_calls_adapter_and_drops(bedrock_root, registry_with_stub):
    rec = create_instance(
        vendor_slug="stub-counter", display_name="ctr",
        credentials_dict={"X": "1"},
    )
    mgr = InstanceManager(adapter_registry=registry_with_stub)
    mgr.start_instance(rec)
    mgr.stop_instance(rec.id)
    assert _CountingAdapter.stops == 1
    assert not mgr.is_running(rec.id)


def test_stop_instance_is_idempotent(bedrock_root, registry_with_stub):
    rec = create_instance(
        vendor_slug="stub-counter", display_name="ctr",
        credentials_dict={"X": "1"},
    )
    mgr = InstanceManager(adapter_registry=registry_with_stub)
    mgr.start_instance(rec)
    mgr.stop_instance(rec.id)
    mgr.stop_instance(rec.id)  # no-op
    assert _CountingAdapter.stops == 1


def test_start_all_persisted_skips_disabled_rows(bedrock_root, registry_with_stub):
    r1 = create_instance(
        vendor_slug="stub-counter", display_name="a",
        credentials_dict={"X": "1"},
    )
    disable_instance(r1.id, disabled_by_operator_id=None, reason="t")
    r2 = create_instance(
        vendor_slug="stub-counter", display_name="b",
        credentials_dict={"X": "2"},
    )
    mgr = InstanceManager(adapter_registry=registry_with_stub)
    summary = mgr.start_all_persisted()
    assert r1.id not in summary["started"]
    assert r2.id in summary["started"]


def test_start_all_persisted_survives_broken_adapter(bedrock_root):
    reg = AdapterRegistry(backend=InMemoryRegistryBackend())
    reg.register_adapter_class(_ExplodingAdapter)
    reg.register_adapter_class(_CountingAdapter)
    _reset_counters()
    broken = create_instance(
        vendor_slug="stub-explode", display_name="ex",
        credentials_dict={"k": "v"},
    )
    healthy = create_instance(
        vendor_slug="stub-counter", display_name="ok",
        credentials_dict={"k": "v"},
    )
    mgr = InstanceManager(adapter_registry=reg)
    summary = mgr.start_all_persisted()
    assert broken.id in summary["failed"]
    assert healthy.id in summary["started"]
    assert _CountingAdapter.starts == 1


def test_stop_all_running_stops_every_started_instance(bedrock_root, registry_with_stub):
    r1 = create_instance(
        vendor_slug="stub-counter", display_name="a",
        credentials_dict={"X": "1"},
    )
    mgr = InstanceManager(adapter_registry=registry_with_stub)
    mgr.start_instance(r1)
    mgr.stop_all_running()
    assert _CountingAdapter.stops == 1
    assert not mgr.is_running(r1.id)
