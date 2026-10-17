"""Wazuh manager + indexer client.

Wazuh 4.x has two HTTP surfaces:

  - Manager API  (port 55000)  — control + agent management + health.
                                  Auth: POST /security/user/authenticate
                                  returns a JWT, used as Bearer for all
                                  subsequent calls.
  - Indexer API  (port 9200)   — OpenSearch fork; the alert data lives
                                  here in `wazuh-alerts-*` indices.
                                  Auth: HTTP basic.

For ingest we mainly hit the indexer. The manager URL is kept for
control operations (smoke test, agent enumeration, group listing for
tenant mapping).

Client is intentionally minimal: requests + tight timeouts, no SDK,
no retry-by-default (caller decides). Verifies TLS by default; can be
toggled off for self-signed environments by env (`WAZUH_TLS_VERIFY=0`).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

import requests

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WazuhConfig:
    """Connection parameters for a configured Wazuh instance.

    Held in registry.db's adapter_instances table; passed to the client
    + poller at adapter start time.
    """
    manager_url: str           # e.g., "https://wazuh-manager:55000"
    indexer_url: str           # e.g., "https://wazuh-indexer:9200"
    api_username: str          # manager API user (for JWT auth)
    api_password: str          # manager API password
    indexer_username: str      # indexer basic-auth user
    indexer_password: str      # indexer basic-auth password
    verify_tls: bool = True
    timeout_seconds: float = 10.0


class WazuhAuthError(Exception):
    """Authentication failed against manager or indexer."""


class WazuhClientError(Exception):
    """Generic network / protocol error talking to Wazuh."""


class WazuhClient:
    """Stateful client — caches the manager JWT until it expires.

    Indexer auth is HTTP basic per call (no token caching needed since
    OpenSearch basic-auth is stateless).
    """

    def __init__(self, config: WazuhConfig) -> None:
        self._config = config
        self._jwt: str | None = None
        self._session = requests.Session()
        if not config.verify_tls:
            self._session.verify = False  # type: ignore[assignment]
            # Suppress urllib3 InsecureRequestWarning at module level;
            # operator opted in via env.
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass

    # ----- Manager: auth + control -----

    def authenticate(self) -> str:
        """Acquire a JWT from the manager. Raises WazuhAuthError on
        4xx, WazuhClientError on transport problems."""
        url = self._config.manager_url.rstrip("/") + "/security/user/authenticate"
        try:
            r = self._session.post(
                url,
                auth=(self._config.api_username, self._config.api_password),
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise WazuhClientError(
                f"manager unreachable at {url}: {type(exc).__name__}"
            ) from exc
        if r.status_code == 401:
            raise WazuhAuthError("manager rejected credentials (401)")
        if r.status_code != 200:
            raise WazuhClientError(
                f"manager auth returned HTTP {r.status_code}"
            )
        body = r.json()
        token = body.get("data", {}).get("token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise WazuhClientError("manager response missing JWT token")
        self._jwt = token
        return token

    def ping_manager(self) -> bool:
        """Lightweight health check. Returns True on 200, False otherwise.
        Used by smoke_test() — does not raise."""
        if self._jwt is None:
            try:
                self.authenticate()
            except (WazuhAuthError, WazuhClientError) as exc:
                logger.info("[wazuh] ping_manager auth failed: %s", exc)
                return False
        url = self._config.manager_url.rstrip("/") + "/"
        try:
            r = self._session.get(
                url,
                headers={"Authorization": f"Bearer {self._jwt}"},
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException:
            return False
        return r.status_code == 200

    def list_agent_groups(self) -> list[dict[str, Any]]:
        """Return the manager's agent group list. Used by the
        onboarding wizard for tenant mapping."""
        if self._jwt is None:
            self.authenticate()
        url = self._config.manager_url.rstrip("/") + "/agents/groups"
        r = self._session.get(
            url,
            headers={"Authorization": f"Bearer {self._jwt}"},
            timeout=self._config.timeout_seconds,
        )
        if r.status_code == 401:
            # Token expired — re-auth once + retry
            self.authenticate()
            r = self._session.get(
                url,
                headers={"Authorization": f"Bearer {self._jwt}"},
                timeout=self._config.timeout_seconds,
            )
        if r.status_code != 200:
            raise WazuhClientError(
                f"agent groups returned HTTP {r.status_code}"
            )
        return list(r.json().get("data", {}).get("affected_items", []))

    # ----- Indexer: alert pull -----

    def fetch_alerts_since(
        self,
        since_iso: str,
        *,
        max_results: int = 500,
    ) -> list[dict[str, Any]]:
        """Pull alerts with `timestamp > since_iso` sorted ascending.

        Returns at most `max_results` alerts. Caller should re-call with
        the timestamp of the LAST returned alert to drain the backlog,
        then sleep + poll again.
        """
        url = self._config.indexer_url.rstrip("/") + "/wazuh-alerts-*/_search"
        query = {
            "size": max_results,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {
                "range": {
                    "timestamp": {"gt": since_iso},
                },
            },
        }
        try:
            r = self._session.post(
                url,
                json=query,
                auth=(
                    self._config.indexer_username,
                    self._config.indexer_password,
                ),
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise WazuhClientError(
                f"indexer unreachable at {url}: {type(exc).__name__}"
            ) from exc
        if r.status_code == 401:
            raise WazuhAuthError("indexer rejected credentials (401)")
        if r.status_code != 200:
            raise WazuhClientError(
                f"indexer search returned HTTP {r.status_code}"
            )
        hits = r.json().get("hits", {}).get("hits", [])
        # Unwrap each hit's `_source` — that's the alert envelope shape
        # the adapter knows how to extract from.
        return [h.get("_source", {}) for h in hits if isinstance(h, dict)]


def config_from_env() -> WazuhConfig:
    """Build a WazuhConfig from environment variables. Used by the
    bundled mode (where the bundle sets these at compose time) and as
    a fallback for adapter instances that haven't loaded their stored
    config yet."""
    return WazuhConfig(
        manager_url=os.environ.get(
            "WAZUH_MANAGER_URL", "https://wazuh-manager:55000",
        ),
        indexer_url=os.environ.get(
            "WAZUH_INDEXER_URL", "https://wazuh-indexer:9200",
        ),
        api_username=os.environ.get("WAZUH_API_USER", "wazuh"),
        api_password=os.environ.get("WAZUH_API_PASSWORD", ""),
        indexer_username=os.environ.get("WAZUH_INDEXER_USER", "admin"),
        indexer_password=os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
        verify_tls=os.environ.get("WAZUH_TLS_VERIFY", "1") not in ("0", "false", "no"),
        timeout_seconds=float(os.environ.get("WAZUH_TIMEOUT_SECONDS", "10")),
    )
