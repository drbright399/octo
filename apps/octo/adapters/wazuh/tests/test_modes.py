"""Wazuh connection modes — existing / import / bundled, + onboarding."""
from __future__ import annotations

from apps.octo.adapters.wazuh import WazuhSourceAdapter
from apps.octo.adapters.wazuh.adapter import _mode
from apps.octo.adapters.wazuh.client import WazuhAuthError, WazuhClientError, WazuhConfig


class _FakeClient:
    def __init__(self, config: WazuhConfig, *, error=None):
        self.config = config
        self._error = error

    def authenticate(self):
        if self._error is not None:
            raise self._error
        return True


def _adapter(error=None):
    return WazuhSourceAdapter(client_factory=lambda c: _FakeClient(c, error=error))


EXISTING = {
    "WAZUH_MODE": "existing",
    "WAZUH_MANAGER_URL": "https://wazuh.local:55000",
    "WAZUH_API_KEY": "k",
}


# --- mode parsing ---

def test_mode_default_and_valid():
    assert _mode({}) == "existing"
    assert _mode({"WAZUH_MODE": "BUNDLED"}) == "bundled"
    assert _mode({"WAZUH_MODE": "import"}) == "import"


def test_mode_unknown_falls_back():
    assert _mode({"WAZUH_MODE": "nonsense"}) == "existing"


# --- credential shape exposes the mode selector ---

def test_credential_shape_has_mode_enum():
    fields = {f.name: f for f in WazuhSourceAdapter().credential_shape()}
    mode = fields["WAZUH_MODE"]
    assert mode.kind == "enum"
    assert mode.choices == ["existing", "import", "bundled"]
    # URL/key optional so bundled doesn't demand them
    assert fields["WAZUH_MANAGER_URL"].required is False
    assert fields["WAZUH_API_KEY"].required is False


# --- smoke test per mode ---

def test_smoke_bundled_without_url_is_provisioning_ack():
    res = _adapter().smoke_test({"WAZUH_MODE": "bundled"})
    assert res.ok is True and "provisioned" in res.message.lower()


def test_smoke_existing_without_url_fails():
    res = _adapter().smoke_test({"WAZUH_MODE": "existing"})
    assert res.ok is False and "required" in res.message.lower()


def test_smoke_import_without_url_fails_with_import_label():
    res = _adapter().smoke_test({"WAZUH_MODE": "import"})
    assert res.ok is False and "import" in res.message.lower()


def test_smoke_existing_with_valid_creds_ok():
    res = _adapter().smoke_test(EXISTING)
    assert res.ok is True and "reachable" in res.message.lower()


def test_smoke_existing_auth_rejected():
    res = _adapter(error=WazuhAuthError("401")).smoke_test(EXISTING)
    assert res.ok is False and "rejected" in res.message.lower()


def test_smoke_existing_unreachable():
    res = _adapter(error=WazuhClientError("conn")).smoke_test(EXISTING)
    assert res.ok is False and "reach" in res.message.lower()


# --- onboarding surfaces the three options ---

def test_onboarding_three_modes():
    ob = WazuhSourceAdapter().onboarding()
    assert ob is not None and ob.webhook_url is None
    titles = " ".join(s.title.lower() for s in ob.steps)
    assert "existing" in titles and "import" in titles and "built-in" in titles
    assert len(ob.steps) == 4
