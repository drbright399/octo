"""The entity token key lives on the SECRETS mount (a sibling of
mfa-key.env), never in the state volume a backup copies; the bundle's
explicit path wins; a dev box without either falls back to the data root."""
from __future__ import annotations

from apps.octo.entity import tokens


def test_the_key_is_a_sibling_of_the_mfa_key_never_in_the_state_volume(tmp_path, monkeypatch):
    secrets_dir = tmp_path / "secrets-mount"
    secrets_dir.mkdir()
    monkeypatch.setenv("OCTO_DATA_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("OCTO_MFA_KEY_PATH", str(secrets_dir / "mfa-key.env"))
    monkeypatch.delenv("OCTO_ENTITY_HMAC_PATH", raising=False)
    tokens.reset_cache()
    try:
        assert tokens.key_path() == (secrets_dir / "entity-hmac.env").resolve()
        version, key = tokens.master()
        assert version == "v1" and len(key) == 32
        assert (secrets_dir / "entity-hmac.env").exists()
        assert not (tmp_path / "state" / "secrets").exists()
        assert oct((secrets_dir / "entity-hmac.env").stat().st_mode & 0o777) == "0o600"
        explicit = tmp_path / "elsewhere" / "entity-hmac.env"
        monkeypatch.setenv("OCTO_ENTITY_HMAC_PATH", str(explicit))
        assert tokens.key_path() == explicit.resolve()
        monkeypatch.delenv("OCTO_ENTITY_HMAC_PATH")
        monkeypatch.delenv("OCTO_MFA_KEY_PATH")
        assert tokens.key_path() == tmp_path / "state" / "secrets" / "entity-hmac.env"
    finally:
        tokens.reset_cache()
