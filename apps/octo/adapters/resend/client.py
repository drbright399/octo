"""Resend API client.

Single-key auth: a Resend API key (``re_...``) in the Authorization header as
a Bearer. Resend **requires** a ``User-Agent`` header — requests without it are
rejected with 403. Base URL ``https://api.resend.com``.

Two responsibilities:
  - onboarding / smoke + domain verification (``GET /domains``)
  - outbound send (``POST /emails``)

No credentials live in this module; the caller supplies them via ``ResendConfig``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests

logger = logging.getLogger(__name__)

RESEND_API_BASE = "https://api.resend.com"
_USER_AGENT = "octo-athena/1.0"  # REQUIRED by Resend; 403 without a User-Agent.


@dataclass(frozen=True)
class ResendConfig:
    api_key: str
    from_addr: str = ""        # default sender, e.g. "Name <athena@domain>"
    domain: str = ""           # sending domain we expect to be verified
    timeout_seconds: float = 20.0
    web_url: str = "https://resend.com"


class ResendAuthError(Exception): ...
class ResendClientError(Exception): ...


class ResendClient:
    def __init__(self, config: ResendConfig) -> None:
        self._config = config
        self._session = requests.Session()

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._config.api_key}",
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def list_domains(self) -> list[dict[str, Any]]:
        """Validates the key (200) and returns the account's sending domains."""
        url = RESEND_API_BASE + "/domains"
        try:
            r = self._session.get(
                url, headers=self._headers(), timeout=self._config.timeout_seconds
            )
        except requests.RequestException as exc:
            raise ResendClientError(f"Resend unreachable: {type(exc).__name__}") from exc
        if r.status_code in (401, 403):
            raise ResendAuthError(f"Resend rejected API key (HTTP {r.status_code})")
        if r.status_code != 200:
            raise ResendClientError(f"Resend /domains returned HTTP {r.status_code}")
        body = r.json()
        data = body.get("data", body) if isinstance(body, dict) else body
        return list(data or [])

    def find_domain(self, name: str) -> dict[str, Any] | None:
        target = (name or "").strip().lower()
        if not target:
            return None
        for dom in self.list_domains():
            if str(dom.get("name", "")).strip().lower() == target:
                return dom
        return None

    def send_email(
        self,
        *,
        to: str | list[str],
        subject: str,
        html: str | None = None,
        text: str | None = None,
        from_addr: str | None = None,
        attachments: list[dict[str, Any]] | None = None,
    ) -> str:
        """POST /emails. Returns the Resend message id. Raises on failure."""
        sender = from_addr or self._config.from_addr
        if not sender:
            raise ResendClientError("send_email: no 'from' address configured")
        payload: dict[str, Any] = {
            "from": sender,
            "to": to if isinstance(to, list) else [to],
            "subject": subject,
        }
        if html is not None:
            payload["html"] = html
        if text is not None:
            payload["text"] = text
        if attachments:
            payload["attachments"] = attachments

        url = RESEND_API_BASE + "/emails"
        try:
            r = self._session.post(
                url,
                json=payload,
                headers=self._headers(json_body=True),
                timeout=self._config.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise ResendClientError(f"Resend unreachable: {type(exc).__name__}") from exc
        if r.status_code in (401, 403):
            raise ResendAuthError(f"Resend rejected API key on send (HTTP {r.status_code})")
        if r.status_code not in (200, 201):
            raise ResendClientError(
                f"Resend /emails returned HTTP {r.status_code}: {r.text[:200]}"
            )
        msg_id = (r.json() or {}).get("id")
        if not msg_id:
            raise ResendClientError("Resend send returned no message id")
        return str(msg_id)
