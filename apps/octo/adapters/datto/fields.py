"""Field access for a Datto alert envelope — shared by normalisation
(`adapter.py`), presentation (`presentation.py`) and link building (`links.py`).

Every read of a vendor STRING goes through `_first()`, so a blank value, a
non-string, or a template variable Datto left unsubstituted is "missing" in
every consumer alike.
"""

from __future__ import annotations

import re
from typing import Any, Optional


# Datto RMM webhook body variables are written in [square_brackets]. The names
# the guided-setup templates use (see onboarding()); a test pins the templates
# to this set. NOTE: the list has no priority and no timestamp variable.
WEBHOOK_TEMPLATE_VARIABLES: frozenset[str] = frozenset({
    "alert_uid", "alert_message", "alert_category", "alert_type",
    "device_hostname", "device_uid", "site_uid", "site_name", "platform",
})

# A leaf is only treated as an unsubstituted token when the WHOLE value is one
# variable: "[lower_snake]" (Datto's form — any name, so a variable Datto does
# not know for this alert type is still caught), or one of the "$Name" tokens
# the earlier templates used (operators may still have those
# pasted in Datto). A loose "starts with $letter" prefix wrongly ate legitimate
# free text like a monitor message "$LASTEXITCODE was 1" or "$Recycle.Bin".
_UNSUBBED_TOKEN_RE = re.compile(
    r"^(?:\[[a-z][a-z0-9_]{1,63}\]"
    r"|\$(?:AlertUID|AlertPriority|AlertType|AlertCategory|AlertMessage|"
    r"DeviceName|DeviceUID|SiteUID|SiteName|Timestamp|TicketNumber))$"
)


# A Datto alert uid is a UUID (8-4-4-4-12 hex). The ONLY shape that is ever
# put into an API request path (`DattoClient.get_alert`) or accepted from the
# raw text of a webhook body that did not parse (`doorbell.read_raw`): a
# templated body is operator-written and vendor-substituted, so anything
# looser would let a body steer what Athena asks the vendor for.
_ALERT_UID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def is_alert_uid(value: Any) -> bool:
    """True when `value` is exactly a Datto alert uid (a UUID string)."""
    return isinstance(value, str) and bool(_ALERT_UID_RE.fullmatch(value))


def _is_unsubstituted_token(value: str) -> bool:
    """True if a leaf is EXACTLY a literal template variable ('[site_uid]',
    or a legacy '$SiteUID') — Datto left it in place because it does not know
    that variable (for this alert type). Such literals must be treated as
    MISSING, never ingested: a literal '[site_uid]' must not become a tenant
    id. Whole-value match only, so real free text survives."""
    return bool(_UNSUBBED_TOKEN_RE.fullmatch(value))


def _first(*candidates: Any) -> Optional[str]:
    """First usable STRING candidate: skips None, non-strings, blank strings,
    and unsubstituted Datto $tokens. Every alert field routed through here is
    string-typed; skipping non-strings keeps a contract-violating numeric/dict
    value (e.g. a non-string siteUid or priority) from flowing downstream and
    crashing the public webhook. Numeric timestamps are handled by _to_iso."""
    for value in candidates:
        if not isinstance(value, str):
            continue
        s = value.strip()
        if not s or _is_unsubstituted_token(s):
            continue
        return s
    return None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


# --- Field aliases -----------------------------------------------------------
# A Datto alert reaches extract_event() in one of TWO shapes and both must
# normalize identically:
#   * WEBHOOK  — flat, operator-templated: alertPriority / device.hostname /
#     siteUid / alertContext.message
#   * API/POLL — the nested /api/v2 alert object the poller feeds in verbatim:
#     priority / alertSourceInfo.deviceName / alertSourceInfo.siteUid /
#     alertContext.@class
# Before these aliases, poll-path alerts silently degraded to severity=info,
# source_host=None, tenant=_unmapped because only the webhook keys were read.

def _alert_priority(env: dict[str, Any]) -> str:
    return _first(env.get("alertPriority"), env.get("priority")) or ""


def _alert_site_uid(env: dict[str, Any]) -> Optional[str]:
    asi = _as_dict(env.get("alertSourceInfo"))
    return _first(env.get("siteUid"), asi.get("siteUid"))


def _alert_host(env: dict[str, Any]) -> Optional[str]:
    device = _as_dict(env.get("device"))
    asi = _as_dict(env.get("alertSourceInfo"))
    return _first(device.get("hostname"), asi.get("deviceName"), env.get("deviceName"))


def _alert_category(env: dict[str, Any]) -> str:
    context = _as_dict(env.get("alertContext"))
    return (
        _first(env.get("alertCategory"), context.get("@class"), env.get("alertType"))
        or "rmm"
    )


def _alert_message(env: dict[str, Any]) -> Optional[str]:
    context = _as_dict(env.get("alertContext"))
    return _first(context.get("message"), context.get("description"), env.get("diagnostics"))


def _alert_uid(env: dict[str, Any]) -> Optional[str]:
    return _first(env.get("alertUid"))


def _alert_device_uid(env: dict[str, Any]) -> Optional[str]:
    device = _as_dict(env.get("device"))
    asi = _as_dict(env.get("alertSourceInfo"))
    return _first(asi.get("deviceUid"), device.get("uid"), env.get("deviceUid"))


def _alert_site_name(env: dict[str, Any]) -> Optional[str]:
    asi = _as_dict(env.get("alertSourceInfo"))
    return _first(asi.get("siteName"), env.get("siteName"))


def _alert_is_resolved(env: dict[str, Any]) -> bool:
    """alert-resolved events carry event=="alert_resolved" (webhook) or a
    truthy `resolved` (API object)."""
    return env.get("event") == "alert_resolved" or bool(env.get("resolved"))
