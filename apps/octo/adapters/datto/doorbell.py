"""Reading a Datto RMM webhook as a DOORBELL — which alert, raised or resolved.

Datto RMM substitutes its [bracketed] variables into the operator's webhook
body template WITHOUT JSON-escaping them. A template carrying
[alert_message] therefore breaks as soon as the message holds a quote or a
line break — every Windows event does — and the webhook arrives as invalid
JSON. Even when such a body parses, it is a different shape from the alert
object the poller stores (no priority, no context class), so one alert
looked different by door.

So the body is read for two things only: the alert uid and whether the bell
says raised or resolved. Athena then fetches the full alert from Datto's API
by that uid (`DattoClient.get_alert`, through the running instance) and
stores THAT — the poller's shape, headline, type and severity. The reading
happens in two modes:

  * the body parsed → the `alertUid` and `event` fields, as values;
  * it did not     → a STRICT scan of the raw text for `"alertUid": "<uuid>"`
                     and `"event": "alert_raised|alert_resolved"`. Nothing
                     else in a body that failed to parse is looked at.

A uid is a UUID (`fields.is_alert_uid`); anything else is not a uid — it is
never fetched, never put into a request path.

The vendor-neutral bookkeeping (one fetch per uid per minute, the instance
budget, the deadline) lives in `instances.doorbell`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from apps.octo.adapters.datto.fields import _first, is_alert_uid

EVENT_RAISED = "alert_raised"
EVENT_RESOLVED = "alert_resolved"
_EVENTS = (EVENT_RAISED, EVENT_RESOLVED)

# Raw-text scan for a body that is not valid JSON. Deliberately narrow: the
# key in double quotes, optional whitespace, the value in double quotes, and
# the value must be EXACTLY a UUID / one of the two event names. The first
# match wins; a body can contain what it likes around it.
_UID_RAW_RE = re.compile(
    r'"alertUid"\s*:\s*"'
    r'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"'
)
_EVENT_RAW_RE = re.compile(r'"event"\s*:\s*"(alert_raised|alert_resolved)"')


@dataclass(frozen=True)
class Doorbell:
    """What a webhook body says about which alert rang, and how."""

    alert_uid: Optional[str] = None     # a lowercase UUID, or None (nothing fetchable)
    event: Optional[str] = None         # EVENT_RAISED / EVENT_RESOLVED / None

    @property
    def resolved(self) -> bool:
        return self.event == EVENT_RESOLVED


def _canonical(uid: Optional[str]) -> Optional[str]:
    # UUIDs are case-insensitive; one spelling keeps the per-uid throttle
    # honest (the same alert in two cases is one alert) and the request path
    # the form Datto itself uses.
    return uid.lower() if uid is not None and is_alert_uid(uid) else None


def read_envelope(envelope: dict[str, Any]) -> Doorbell:
    """The bell from a body that parsed. A uid that is not shaped like one
    (a literal '[alert_uid]' from Datto's own test, a hand-typed id) yields
    no uid: the body is then handled as the templated event it is."""
    event = envelope.get("event")
    return Doorbell(
        alert_uid=_canonical(_first(envelope.get("alertUid"))),
        event=event if event in _EVENTS else None,
    )


def read_raw(body: bytes) -> Doorbell:
    """The bell from a body that did NOT parse. Decoded leniently (bytes
    outside UTF-8 cannot be part of a match anyway) and scanned for exactly
    the two quoted fields; nothing else is read."""
    text = body.decode("utf-8", errors="replace")
    uid = _UID_RAW_RE.search(text)
    event = _EVENT_RAW_RE.search(text)
    return Doorbell(
        alert_uid=_canonical(uid.group(1)) if uid else None,
        event=event.group(1) if event else None,
    )


def as_delivered(alert: dict[str, Any], bell: Doorbell) -> dict[str, Any]:
    """The fetched object as THIS bell reports it.

    A resolved bell yields an object that says so through Datto's own
    `resolved` flag (set only when the API copy does not already), so the
    stored row reads '[resolved] …' exactly as a templated resolved body did
    — and is its own row, distinct from the raised one, as today. A raised
    bell leaves the object exactly as the API answered it: that is the copy
    the poller stores, so the sink collapses the two."""
    if bell.resolved and not alert.get("resolved"):
        return {**alert, "resolved": True}
    return alert
