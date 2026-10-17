"""Email sender — Postfix relay client.

Talks to a Postfix relay reachable inside the deployment's private
network over SMTP submission. Postfix is the auth gateway to the
upstream smart-host (Gmail / Postmark / etc.); this module never sees
the upstream credentials.

The module is intentionally small: one `send_email()` function, no
class hierarchy, no template engine. Body strings are caller-built;
recipients are passed in. No retry — caller decides how to react to
failure (e.g., the forgot-password endpoint logs but still returns 202
to preserve anti-enumeration timing).

Provider switch (EMAIL_PROVIDER, default "postfix"):
  postfix  — SMTP submission to the on-tailnet Postfix relay (above).
  resend   — Resend HTTP API (api.resend.com). Reads RESEND_API_KEY and
             RESEND_FROM from the environment. This is the env-injected seam
             for internal testing / single-account deploys; a later slice can
             resolve the active "resend" integration instance's vaulted creds
             instead of env. The send path reuses the Resend adapter client.

Operator notices (v0.10 — the other admins told of a single-person tenant
change) send ONLY through the configured 'resend' integration instance
(`resend_instance_mailer`), whatever EMAIL_PROVIDER says: a deployment
without one records "not configured" and sends nothing.

Configuration via env (with placeholder defaults so unit tests don't
have to set anything — production deploys MUST set POSTFIX_RELAY_HOST
to the actual relay address):
  POSTFIX_RELAY_HOST       default: postfix-relay.local
  POSTFIX_RELAY_PORT       default: 2525
  POSTFIX_RELAY_FROM       default: notifications@athena.local
  POSTFIX_RELAY_TIMEOUT    default: 10  (seconds)

Failure mode: log + return False. Never raise to caller. The caller
audits the failure separately so we never silently lose a delivery.
"""

from __future__ import annotations

import logging
import os
import smtplib
import socket
from email.message import EmailMessage
from typing import Callable

logger = logging.getLogger(__name__)


def _config() -> dict:
    return {
        "host": os.environ.get("POSTFIX_RELAY_HOST", "postfix-relay.local"),
        "port": int(os.environ.get("POSTFIX_RELAY_PORT", "2525")),
        "from_addr": os.environ.get(
            "POSTFIX_RELAY_FROM", "notifications@athena.local",
        ),
        "timeout": int(os.environ.get("POSTFIX_RELAY_TIMEOUT", "10")),
    }


def _provider() -> str:
    return os.environ.get("EMAIL_PROVIDER", "postfix").strip().lower()


def _resend_creds_from_instance() -> dict:
    """Best-effort load of the active 'resend' integration instance's creds
    from the vault. Returns {} if none configured or on any error — the caller
    falls back to env. Never raises (honors the email_sender contract)."""
    try:
        from apps.octo import credentials
        from apps.octo.instances import list_instances
    except Exception:  # noqa: BLE001 — module may be unavailable in some contexts
        return {}
    try:
        inst = next(
            (r for r in list_instances(include_disabled=False)
             if r.vendor_slug == "resend"),
            None,
        )
        if inst is None:
            return {}
        loaded = credentials.load(inst.cred_ref)
        return loaded if isinstance(loaded, dict) else {}
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "[email] could not load resend instance creds: %s", type(exc).__name__
        )
        return {}


def resend_instance_mailer(
    *, timeout_seconds: float = 10.0,
) -> Callable[[str, str, str], bool] | None:
    """A sender bound to the operator-configured 'resend' INTEGRATION
    INSTANCE — never the env seam, never the Postfix relay — or None when
    no such instance is configured (no API key, or no RESEND_FROM sender on
    it): the caller records "not configured" and attempts nothing.

    The credentials are loaded once; the returned callable
    `(to, subject, body_text) -> bool` never raises (this module's
    contract) and logs the failure CLASS only."""
    creds = _resend_creds_from_instance()
    api_key = str(creds.get("RESEND_API_KEY") or "").strip()
    sender = str(creds.get("RESEND_FROM") or "").strip()
    if not api_key or not sender:
        return None

    def _send(to: str, subject: str, body_text: str) -> bool:
        try:
            from apps.octo.adapters.resend.client import ResendClient, ResendConfig

            client = ResendClient(ResendConfig(
                api_key=api_key, from_addr=sender, timeout_seconds=timeout_seconds,
            ))
            client.send_email(to=to, subject=subject, text=body_text, from_addr=sender)
            return True
        except Exception as exc:  # noqa: BLE001 — never raise to caller
            logger.error(
                "[email] resend (integration) send failed subject=%r err=%s",
                subject, type(exc).__name__,
            )
            return False

    return _send


def _send_via_resend(
    to: str,
    subject: str,
    body_text: str,
    *,
    body_html: str | None = None,
    from_addr: str | None = None,
) -> bool:
    """Send via the Resend HTTP API. Honors the never-raise contract.

    Credentials resolve from the operator-configured 'resend' integration
    instance (BYOK creds in the vault) first, falling back to RESEND_API_KEY /
    RESEND_FROM env vars (the internal-testing / single-account seam).
    """
    creds = _resend_creds_from_instance()
    api_key = (creds.get("RESEND_API_KEY") or os.environ.get("RESEND_API_KEY", "")).strip()
    if not api_key:
        logger.error(
            "[email] EMAIL_PROVIDER=resend but no RESEND_API_KEY (instance or env)"
        )
        return False
    sender = (
        from_addr
        or creds.get("RESEND_FROM")
        or os.environ.get("RESEND_FROM")
        or os.environ.get("POSTFIX_RELAY_FROM", "notifications@athena.local")
    )
    try:
        from apps.octo.adapters.resend.client import ResendClient, ResendConfig

        client = ResendClient(ResendConfig(api_key=api_key, from_addr=sender))
        msg_id = client.send_email(
            to=to, subject=subject, text=body_text, html=body_html, from_addr=sender
        )
        logger.info(
            "[email] delivered via resend id=%s to=%s subject=%r", msg_id, to, subject
        )
        return True
    except Exception as exc:  # noqa: BLE001 — never raise to caller
        logger.error(
            "[email] resend send failed to=%s subject=%r err=%s",
            to, subject, type(exc).__name__,
        )
        return False


def send_email(
    to: str,
    subject: str,
    body_text: str,
    *,
    body_html: str | None = None,
    from_addr: str | None = None,
) -> bool:
    """Send a single email via the Postfix relay.

    Returns True on apparent success (relay accepted the message), False
    on any failure. Never raises.

    `body_html` is optional; if provided, the message is multipart
    (text/plain + text/html) so clients render whichever they prefer.

    `from_addr` overrides the default `POSTFIX_RELAY_FROM` for one-off
    sends; most callers should pass None and let the env default win so
    a future provider swap doesn't require code changes.
    """
    if _provider() == "resend":
        return _send_via_resend(
            to, subject, body_text, body_html=body_html, from_addr=from_addr
        )

    cfg = _config()
    sender = from_addr or cfg["from_addr"]

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"]) as smtp:
            # Postfix relay accepts unauthenticated SMTP submission from
            # tailnet-internal sources; auth happens between Postfix and
            # the upstream smart-host, not between us and Postfix.
            smtp.send_message(msg)
        logger.info("[email] delivered to=%s subject=%r", to, subject)
        return True
    except (smtplib.SMTPException, OSError, socket.error) as exc:
        # Catch broadly: SMTP errors, connection refusals, timeouts.
        # Don't leak the exception body to callers — they get False
        # and decide whether to surface to the user.
        logger.error(
            "[email] send failed to=%s subject=%r host=%s:%s err=%s",
            to, subject, cfg["host"], cfg["port"], type(exc).__name__,
        )
        return False
