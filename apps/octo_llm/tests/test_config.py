"""Tests for octo-llm config loading.

Defaults come up clean. Unknown backend names raise. Out-of-range
numeric values raise. Env-var override path works.
"""
from __future__ import annotations

import pytest

from apps.octo_llm.config import load_settings


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """No env set → stub backend + sane defaults."""
    for var in (
        "OCTO_LLM_BACKEND", "OCTO_LLM_MODEL_PATH", "OCTO_LLM_THREADS",
        "OCTO_LLM_CONTEXT_TOKENS", "OCTO_LLM_MAX_OUTPUT_TOKENS",
        "OCTO_LLM_REQUEST_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)
    s = load_settings()
    assert s.backend == "stub"
    assert s.stub_mode is True
    assert s.threads == -1
    assert s.context_tokens == 4096
    assert s.max_output_tokens == 512
    assert s.request_timeout_seconds == 30.0


def test_backend_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OCTO_LLM_BACKEND", "llama-cpp")
    s = load_settings()
    assert s.backend == "llama-cpp"
    assert s.stub_mode is False


def test_unknown_backend_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OCTO_LLM_BACKEND", "ollama")
    with pytest.raises(RuntimeError, match="must be one of"):
        load_settings()


def test_non_integer_threads_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OCTO_LLM_THREADS", "lots")
    with pytest.raises(RuntimeError, match="OCTO_LLM_THREADS"):
        load_settings()


def test_context_tokens_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """A typo-low context window should refuse to boot rather than
    cause runtime confusion."""
    monkeypatch.setenv("OCTO_LLM_CONTEXT_TOKENS", "16")
    with pytest.raises(RuntimeError, match=">= 256"):
        load_settings()


def test_max_output_tokens_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OCTO_LLM_MAX_OUTPUT_TOKENS", "4")
    with pytest.raises(RuntimeError, match=">= 16"):
        load_settings()


def test_request_timeout_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OCTO_LLM_REQUEST_TIMEOUT_SECONDS", "0.1")
    with pytest.raises(RuntimeError, match=">= 1.0"):
        load_settings()


def test_empty_string_env_falls_through_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operators sometimes set env vars to empty string. That's the
    same as 'not set' — use the default."""
    monkeypatch.setenv("OCTO_LLM_THREADS", "")
    s = load_settings()
    assert s.threads == -1
