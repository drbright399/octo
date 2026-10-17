"""A poller re-lists an open alert every cycle; the drop counter must count the
alert once, not once per poll."""
from __future__ import annotations

import pytest

from apps.octo.instances import unmapped


@pytest.fixture(autouse=True)
def _clean():
    unmapped.reset()
    yield
    unmapped.reset()


def test_same_event_is_counted_once_but_other_events_still_count():
    for _ in range(50):
        unmapped.record_drop(7, "site-a", event_key="alert-1")
    assert unmapped.snapshot(7)["dropped"] == 1
    assert unmapped.is_repeat_drop(7, "alert-1") is True
    assert unmapped.is_repeat_drop(7, "alert-2") is False
    assert unmapped.record_drop(7, "site-a", event_key="alert-2") == 2


def test_without_an_event_key_every_drop_counts():
    unmapped.record_drop(7, "site-a")
    unmapped.record_drop(7, "site-a")
    assert unmapped.snapshot(7)["dropped"] == 2


def test_seen_keys_are_bounded_and_per_instance(monkeypatch):
    monkeypatch.setattr(unmapped, "MAX_SEEN_EVENT_KEYS", 3)
    for i in range(5):
        unmapped.record_drop(7, "site-a", event_key=f"alert-{i}")
    assert unmapped.is_repeat_drop(7, "alert-0") is False   # aged out
    assert unmapped.is_repeat_drop(7, "alert-4") is True
    assert unmapped.is_repeat_drop(8, "alert-4") is False    # other instance


def test_reset_forgets_seen_events():
    unmapped.record_drop(7, "site-a", event_key="alert-1")
    unmapped.reset(7)
    assert unmapped.is_repeat_drop(7, "alert-1") is False
