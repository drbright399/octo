"""octo-llm runtime configuration.

Settings come from environment variables. Defaults are dev-friendly
(stub mode, no model required). Production deployments override via
the bundle's compose env block.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Settings constants (the bundle side: docs/operations/bundle.md).

# Inference backend selection. "stub" returns canned responses
# (default, dev-friendly, no model weights needed). "llama-cpp" loads
# a real GGUF model — only available after Slice 2 lands. Future
# backends (e.g., "ollama") plug in here.
_BACKEND_ENV = "OCTO_LLM_BACKEND"
_DEFAULT_BACKEND = "stub"

# Path to the GGUF model file when backend = "llama-cpp". Ignored in
# stub mode. Production volume-mounts the model into the container.
_MODEL_PATH_ENV = "OCTO_LLM_MODEL_PATH"
_DEFAULT_MODEL_PATH = "/var/lib/octo-llm/models/granite-3b-q4.gguf"

# Threads to use for inference. -1 = use all cores. Production tunes
# this against the host's CPU count + headroom for octo-core.
_THREADS_ENV = "OCTO_LLM_THREADS"
_DEFAULT_THREADS = -1

# Context window. Granite 3B supports up to 128k; we cap lower to
# bound prompt size + memory.
_CONTEXT_TOKENS_ENV = "OCTO_LLM_CONTEXT_TOKENS"
_DEFAULT_CONTEXT_TOKENS = 4096

# Max tokens generated per call. Bounds wall-clock per request and
# prevents an attacker who got past the structured-input guard from
# triggering an unbounded generation loop.
_MAX_OUTPUT_TOKENS_ENV = "OCTO_LLM_MAX_OUTPUT_TOKENS"
_DEFAULT_MAX_OUTPUT_TOKENS = 512

# Hard wall-clock cap per request in seconds. Beyond this, the server
# raises a timeout. Defends against runaway generation + GIL-bound
# stalls.
_REQUEST_TIMEOUT_ENV = "OCTO_LLM_REQUEST_TIMEOUT_SECONDS"
_DEFAULT_REQUEST_TIMEOUT = 30.0


@dataclass(frozen=True)
class Settings:
    """Runtime settings, loaded once at app startup.

    Frozen so config drift mid-request is impossible. To change a
    setting, restart the container.
    """
    backend: str
    model_path: Path
    threads: int
    context_tokens: int
    max_output_tokens: int
    request_timeout_seconds: float

    @property
    def stub_mode(self) -> bool:
        return self.backend == "stub"


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    try:
        return int(val)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer, got {val!r}")


def _env_float(name: str, default: float) -> float:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    try:
        return float(val)
    except ValueError:
        raise RuntimeError(f"{name} must be a float, got {val!r}")


def load_settings() -> Settings:
    """Read environment and return the active Settings.

    Validates ranges so a typo turns into a refuse-to-boot error
    instead of silent misbehavior at request time.
    """
    backend = os.environ.get(_BACKEND_ENV, _DEFAULT_BACKEND).lower().strip()
    if backend not in {"stub", "llama-cpp"}:
        raise RuntimeError(
            f"{_BACKEND_ENV} must be one of: stub, llama-cpp (got {backend!r})"
        )

    model_path = Path(os.environ.get(_MODEL_PATH_ENV, _DEFAULT_MODEL_PATH))
    threads = _env_int(_THREADS_ENV, _DEFAULT_THREADS)
    context_tokens = _env_int(_CONTEXT_TOKENS_ENV, _DEFAULT_CONTEXT_TOKENS)
    max_output_tokens = _env_int(_MAX_OUTPUT_TOKENS_ENV, _DEFAULT_MAX_OUTPUT_TOKENS)
    request_timeout_seconds = _env_float(_REQUEST_TIMEOUT_ENV, _DEFAULT_REQUEST_TIMEOUT)

    if context_tokens < 256:
        raise RuntimeError(
            f"{_CONTEXT_TOKENS_ENV} must be >= 256 (got {context_tokens})"
        )
    if max_output_tokens < 16:
        raise RuntimeError(
            f"{_MAX_OUTPUT_TOKENS_ENV} must be >= 16 (got {max_output_tokens})"
        )
    if request_timeout_seconds < 1.0:
        raise RuntimeError(
            f"{_REQUEST_TIMEOUT_ENV} must be >= 1.0 (got {request_timeout_seconds})"
        )

    return Settings(
        backend=backend,
        model_path=model_path,
        threads=threads,
        context_tokens=context_tokens,
        max_output_tokens=max_output_tokens,
        request_timeout_seconds=request_timeout_seconds,
    )
