"""Resend source adapter.

Resend (resend.com) is the platform's outbound email provider, onboarded by an
operator in the Integrations tab (BYOK: their own API key + verified sending
domain). Auth model: single API key (bearer ``re_...``; Resend also requires a
``User-Agent`` header on every request).

Outbound send lives in ``apps.octo.auth.email_sender`` (EMAIL_PROVIDER=resend).
This adapter provides the catalog entry, credential wizard, domain-verification
smoke test, and normalization of Resend delivery webhooks into OCTO events.
"""

from apps.octo.adapters.resend.adapter import ResendSourceAdapter

ResendSourceAdapter.__module__ = "apps.octo.adapters.resend"

__all__ = ["ResendSourceAdapter"]
