"""A pasted Password (Secret) with a space or line break at either end is
the most common Autotask 401; the wizard says so instead of sending it."""
from __future__ import annotations

import pytest

from apps.octo.adapters.autotask.adapter import _config_from_credentials


@pytest.mark.parametrize("secret", ["s3cret-value ", " s3cret-value", "s3cret-value\n", "\ts3cret-value"])
def test_a_secret_with_edge_whitespace_is_refused_with_a_clear_message(secret):
    with pytest.raises(ValueError, match="space or line break"):
        _config_from_credentials({
            "AUTOTASK_USERNAME": "abc123key@example.test",
            "AUTOTASK_SECRET": secret,
            "AUTOTASK_INTEGRATION_CODE": "EXAMPLECODE",
            "AUTOTASK_ZONE_URL": "https://webservices0.example.test/atservicesrest/",
        })


def test_the_username_message_names_the_key_not_a_login_email():
    with pytest.raises(ValueError, match=r"Username \(Key\)"):
        _config_from_credentials({"AUTOTASK_SECRET": "x", "AUTOTASK_INTEGRATION_CODE": "y"})
