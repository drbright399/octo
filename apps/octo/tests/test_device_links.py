"""`instances.device_links` — the per-instance cache, failure memory and
vendor-read budget behind "open device in the vendor portal".

Pure in-process state; the clock is the only thing replaced.
"""
from __future__ import annotations

import pytest

from apps.octo.instances import device_links as dl

PORTAL = "https://exampleplat.rmm.datto.com"
DEVICE = dl.CachedDevice(portal_url=f"{PORTAL}/device/4242", vendor_tenant_id="site-uid-0001")


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    dl.reset()
    now = {"t": 1000.0}
    monkeypatch.setattr(dl, "_monotonic", lambda: now["t"])
    yield now
    dl.reset()


def test_store_lookup_and_ttl(clock):
    dl.store(1, "cred-a", "dev-1", DEVICE)
    assert dl.lookup(1, "cred-a", "dev-1") == DEVICE
    clock["t"] += dl.CACHE_TTL_SEC - 1
    assert dl.lookup(1, "cred-a", "dev-1") == DEVICE
    clock["t"] += 2
    assert dl.lookup(1, "cred-a", "dev-1") is None
    assert dl.cached_count(1) == 0            # an expired entry is dropped, not kept


def test_the_cache_is_per_instance_and_per_credential_set():
    dl.store(1, "cred-a", "dev-1", DEVICE)
    assert dl.lookup(2, "cred-a", "dev-1") is None
    assert dl.lookup(1, "cred-b", "dev-1") is None
    # Storing under a new cred_ref starts from nothing for that instance.
    dl.store(1, "cred-b", "dev-2", DEVICE)
    assert dl.lookup(1, "cred-a", "dev-1") is None and dl.cached_count(1) == 1


def test_the_cache_is_bounded_and_evicts_the_least_recently_used(monkeypatch):
    monkeypatch.setattr(dl, "MAX_CACHED_DEVICES_PER_INSTANCE", 3)
    for n in range(3):
        dl.store(1, "cred-a", f"dev-{n}", DEVICE)
    assert dl.lookup(1, "cred-a", "dev-0") == DEVICE      # touch: now most recent
    dl.store(1, "cred-a", "dev-3", DEVICE)
    assert dl.cached_count(1) == 3
    assert dl.lookup(1, "cred-a", "dev-1") is None        # the oldest untouched one went
    assert dl.lookup(1, "cred-a", "dev-0") == DEVICE


def test_reset_clears_one_instance_or_all():
    dl.store(1, "cred-a", "dev-1", DEVICE)
    dl.store(2, "cred-a", "dev-1", DEVICE)
    dl.reset(1)
    assert dl.lookup(1, "cred-a", "dev-1") is None and dl.lookup(2, "cred-a", "dev-1") == DEVICE
    dl.reset()
    assert dl.lookup(2, "cred-a", "dev-1") is None


def test_a_failure_is_replayed_briefly_then_forgotten(clock, monkeypatch):
    dl.remember_failure(1, "cred-a", "dev-1", code="NOT_FOUND", message="gone")
    failed = dl.recent_failure(1, "cred-a", "dev-1")
    assert (failed.code, failed.message) == ("NOT_FOUND", "gone")
    assert 1 <= failed.retry_in_sec <= dl.FAILURE_THROTTLE_SEC
    assert dl.recent_failure(1, "cred-b", "dev-1") is None
    assert dl.recent_failure(1, "cred-a", "dev-2") is None
    clock["t"] += dl.FAILURE_THROTTLE_SEC + 1
    assert dl.recent_failure(1, "cred-a", "dev-1") is None
    # A success wipes the failure; the memory itself is bounded.
    dl.remember_failure(1, "cred-a", "dev-1", code="NOT_FOUND", message="gone")
    dl.store(1, "cred-a", "dev-1", DEVICE)
    assert dl.recent_failure(1, "cred-a", "dev-1") is None
    monkeypatch.setattr(dl, "MAX_REMEMBERED_FAILURES_PER_INSTANCE", 2)
    for n in range(5):
        dl.remember_failure(1, "cred-a", f"x-{n}", code="NOT_FOUND", message="gone")
    assert dl.recent_failure(1, "cred-a", "x-0") is None
    assert dl.recent_failure(1, "cred-a", "x-4") is not None


def test_a_refusal_for_one_client_is_not_replayed_to_another(clock):
    """A 'not mapped to this client' refusal depends on WHO asked: it is
    remembered per (device, client) — another tenant's analyst gets their own
    answer, and a plain per-device failure still covers everyone."""
    dl.remember_failure(1, "cred-a", "dev-1", code="ISOLATION_VIOLATION", message="not yours",
                        for_client="acme")
    assert dl.recent_failure(1, "cred-a", "dev-1", for_client="acme").code == "ISOLATION_VIOLATION"
    assert dl.recent_failure(1, "cred-a", "dev-1", for_client="globex") is None
    assert dl.recent_failure(1, "cred-a", "dev-1") is None
    clock["t"] += dl.FAILURE_THROTTLE_SEC + 1
    assert dl.recent_failure(1, "cred-a", "dev-1", for_client="acme") is None
    # A per-device failure (the vendor's answer) is seen by every client.
    dl.remember_failure(1, "cred-a", "dev-1", code="NOT_FOUND", message="gone")
    assert dl.recent_failure(1, "cred-a", "dev-1", for_client="globex").code == "NOT_FOUND"


def test_rejected_credentials_are_remembered_for_the_whole_instance(clock):
    """A lookup without a valid token is a credential grant: after one was
    refused, no OTHER device's click may trigger the next one either."""
    dl.remember_failure(
        1, "cred-a", "dev-1", code="VENDOR_CREDENTIALS_REJECTED", message="rejected",
        whole_instance=True,
    )
    assert dl.recent_failure(1, "cred-a", "dev-2").code == "VENDOR_CREDENTIALS_REJECTED"
    assert dl.recent_failure(2, "cred-a", "dev-2") is None
    clock["t"] += dl.FAILURE_THROTTLE_SEC + 1                # longer than a plain failure
    assert dl.recent_failure(1, "cred-a", "dev-2") is not None
    clock["t"] += dl.AUTH_FAILURE_THROTTLE_SEC
    assert dl.recent_failure(1, "cred-a", "dev-2") is None


def test_the_vendor_read_budget_is_a_sliding_minute_per_instance(clock):
    for _ in range(dl.VENDOR_READS_PER_MINUTE):
        assert dl.take_vendor_read(1, "cred-a") == 0
    wait = dl.take_vendor_read(1, "cred-a")
    assert 1 <= wait <= 60
    assert dl.take_vendor_read(2, "cred-a") == 0           # another instance: its own budget
    clock["t"] += 61
    assert dl.take_vendor_read(1, "cred-a") == 0


@pytest.mark.parametrize("url, ok", [
    (f"{PORTAL}/device/4242", True),
    (f"{PORTAL}/anything/else", True),                     # the path scheme is the adapter's check
    ("https://evil.example.test/device/4242", False),
    (f"{PORTAL}.evil.example.test/device/4242", False),
    ("https://exampleplat.rmm.datto.com@evil.example.test/device/4242", False),
    ("https://exampleplat.rmm.datto.com:8443/device/4242", False),
    ("http://exampleplat.rmm.datto.com/device/4242", False),
    (f"{PORTAL}/device/4242?x=1", False),
    (f"{PORTAL}/device/4242#x", False),
    (f"{PORTAL}//evil.example.test", False),
    (f"{PORTAL}\\@evil.example.test/", False),
    (f"{PORTAL}/device/4242\n", False),
    (PORTAL, False),
    (f"{PORTAL}/" + "a" * 400, False),
    (None, False), (4242, False),
])
def test_checked_url_is_a_host_allowlist(url, ok):
    assert dl.checked_url(url, PORTAL) == (url if ok else None)


def test_per_client_failure_key_cannot_be_forged_by_a_crafted_uid():
    """A payload-supplied uid containing a separator must not let a failure
    remembered for one client replay for another (or for the plain key)."""
    from apps.octo.instances import device_links as dl

    dl.reset()
    dl.remember_failure(1, "cred", "dev-1", code="X", message="m", for_client="acme")
    # A uid that *looks* like "dev-1 for acme" under naive string joining
    assert dl.recent_failure(1, "cred", "dev-1|acme") is None
    assert dl.recent_failure(1, "cred", "dev-1", for_client="beta") is None
    assert dl.recent_failure(1, "cred", "dev-1", for_client="acme") is not None
    dl.reset()
