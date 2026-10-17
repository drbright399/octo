"""Suite-wide guard: no test ever reaches the internet through the remote-IP
enrichment (v0.17.2). Enrichment is OFF for every test unless the test turns
it on itself — and those tests pass a fake lookup (no DoH, no RDAP, no
system resolver, never the remote address)."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_live_ip_enrichment(monkeypatch):
    from apps.octo.enrich import worker

    monkeypatch.setenv(worker.ENV, "off")
    worker.set_current(None)
    yield
    worker.set_current(None)
