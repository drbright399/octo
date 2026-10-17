"""Tests for the model sha256 integrity verifier.

Slice 9d (consensus reviewer C5). Covers:
  * happy path — pinned hash matches → verified
  * mismatch — raises ModelIntegrityError, refuses load
  * unpinned (sha256: null in manifest) → byom_no_pin warning
  * unknown model (not in manifest) → byom_unknown_model warning
  * missing file → ModelIntegrityError
  * manifest malformed → falls back to BYOM warn (doesn't block boot)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterator

import pytest

from apps.octo_llm.integrity import (
    ModelIntegrityError,
    compute_sha256,
    verify_or_raise,
)


@pytest.fixture
def tmp_model(tmp_path: Path) -> Iterator[tuple[Path, str]]:
    """Write a small deterministic GGUF-shaped file + return its
    path + sha256. The file content doesn't have to be a real GGUF
    — the verifier only hashes bytes."""
    payload = b"GGUF" + b"\x00" * 1024 + b"fake-model-bytes"
    p = tmp_path / "test-model.gguf"
    p.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    yield p, digest


@pytest.fixture
def manifest_in(monkeypatch, tmp_path: Path):
    """Redirect the integrity module's _MANIFEST_PATH to a temp
    file so each test composes its own manifest content. Returns a
    callable that writes a manifest dict to the temp path."""
    from apps.octo_llm import integrity as integ_mod
    p = tmp_path / "manifest.json"
    monkeypatch.setattr(integ_mod, "_MANIFEST_PATH", p)

    def _write(payload: dict) -> None:
        p.write_text(json.dumps(payload))

    return _write


def test_verify_passes_when_pinned_hash_matches(tmp_model, manifest_in):
    """The happy path — file's computed sha256 matches the manifest's
    pinned value → verifier returns status=verified."""
    path, digest = tmp_model
    manifest_in({
        "manifest_version": 1,
        "models": [{"name": "test-model", "sha256": digest}],
    })
    result = verify_or_raise("test-model", path)
    assert result["status"] == "verified"
    assert result["expected_sha256"] == digest
    assert result["computed_sha256"] == digest


def test_verify_raises_on_mismatch(tmp_model, manifest_in):
    """The headline invariant — if the manifest pins a hash and the
    file hashes to something different, the verifier MUST raise
    rather than allow load."""
    path, _ = tmp_model
    bogus = "0" * 64
    manifest_in({
        "manifest_version": 1,
        "models": [{"name": "test-model", "sha256": bogus}],
    })
    with pytest.raises(ModelIntegrityError) as excinfo:
        verify_or_raise("test-model", path)
    assert "mismatch" in str(excinfo.value).lower()
    assert bogus in str(excinfo.value)  # expected hash shown
    assert "Refusing to load" in str(excinfo.value)


def test_verify_warns_on_unpinned_byom(tmp_model, manifest_in, caplog):
    """BYOM path — manifest has the model name but sha256 is null.
    Verifier logs a warning + returns byom_no_pin status, but does
    NOT raise. This is what enables operators to drop in custom
    models while still surfacing the unverified state in healthz."""
    path, _ = tmp_model
    manifest_in({
        "manifest_version": 1,
        "models": [{"name": "test-model", "sha256": None}],
    })
    with caplog.at_level("WARNING", logger="octo_llm.integrity"):
        result = verify_or_raise("test-model", path)
    assert result["status"] == "byom_no_pin"
    assert result["expected_sha256"] is None
    assert any("not verified" in r.message.lower() for r in caplog.records)


def test_verify_warns_on_unknown_model(tmp_model, manifest_in, caplog):
    """The model name isn't in the manifest at all (the operator
    dropped a file we've never heard of). Same byom semantics with
    a more specific status name."""
    path, _ = tmp_model
    manifest_in({
        "manifest_version": 1,
        "models": [{"name": "some-other-model", "sha256": "a" * 64}],
    })
    with caplog.at_level("WARNING", logger="octo_llm.integrity"):
        result = verify_or_raise("test-model", path)
    assert result["status"] == "byom_unknown_model"


def test_verify_raises_on_missing_file(tmp_path, manifest_in):
    """The verifier is the right layer to surface missing-file
    errors with a meaningful message. ModelIntegrityError carries
    the path that was missing."""
    manifest_in({"manifest_version": 1, "models": []})
    with pytest.raises(ModelIntegrityError) as excinfo:
        verify_or_raise("test-model", tmp_path / "nonexistent.gguf")
    assert "not found" in str(excinfo.value)


def test_verify_treats_malformed_manifest_as_byom(
    tmp_model, monkeypatch, tmp_path, caplog,
):
    """If manifest.json is corrupt (broken JSON), the verifier
    falls through to BYOM-warn rather than blocking boot. This is
    important during dev: a half-edited manifest shouldn't take the
    sibling down."""
    from apps.octo_llm import integrity as integ_mod
    bad = tmp_path / "manifest.json"
    bad.write_text("not valid json {{{")
    monkeypatch.setattr(integ_mod, "_MANIFEST_PATH", bad)
    path, _ = tmp_model
    with caplog.at_level("WARNING", logger="octo_llm.integrity"):
        result = verify_or_raise("test-model", path)
    assert result["status"] in {"byom_no_pin", "byom_unknown_model"}


def test_compute_sha256_matches_hashlib(tmp_model):
    """The streaming compute_sha256 helper must produce the same
    digest as hashlib.sha256 on the same bytes. Confirms our 4MB
    chunk loop doesn't drop trailing bytes or double-feed."""
    path, expected = tmp_model
    assert compute_sha256(path) == expected


def test_factory_manifest_has_pinned_hashes_for_all_models():
    """Regression guard for the live manifest. Every model in
    apps/octo_llm/manifest.json must have a non-null sha256 of
    exactly 64 hex chars. This test exists so that a future code
    review adding a new model entry can't silently land with
    sha256: null and bypass verification on production deploys."""
    import re
    from apps.octo_llm.integrity import _MANIFEST_PATH
    raw = json.loads(_MANIFEST_PATH.read_text())
    for entry in raw.get("models", []):
        name = entry.get("name", "<unnamed>")
        sha = entry.get("sha256")
        assert isinstance(sha, str), (
            f"manifest entry {name!r} has sha256: null — every "
            f"production model MUST be hash-pinned. If this is a "
            f"new addition, run sha256sum on the file and pin it."
        )
        assert re.fullmatch(r"[0-9a-f]{64}", sha), (
            f"manifest entry {name!r} has malformed sha256 {sha!r}"
        )
