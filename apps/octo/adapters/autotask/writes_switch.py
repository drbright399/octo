"""The PSA writes kill switch (slice 0, v0.16.2): is Athena allowed to write
to Autotask at all?

ONE non-secret key on the Autotask adapter instance's `instance_config_json`
(registry `adapter_instances`, so it survives every restart and needs no
migration): `writes_enabled`. Default OFF. Only the JSON value `true` turns it
on; anything else (missing, `false`, `"true"`, `1`) is off.

While it is off, NO write of any kind reaches Autotask:
  - the adapter never constructs or starts the `AutotaskPusher`;
  - both enqueue paths (`POST /tickets/{slug}` with `push_to_autotask`, and
    `POST /tickets/{slug}/{id}/push-to-autotask`) answer 409
    `PSA_WRITES_DISABLED` and queue nothing;
  - a pusher that is somehow running re-reads the switch from the registry
    before every send and refuses (defense in depth: a live switch-off whose
    stop could not be delivered still sends nothing);
  - `GET /tickets/_meta` reports `psa_writes_enabled: false`, and the console
    hides the push option.

Flipping it: `PUT /api/v1/admin/psa/instances/{id}/settings` — super_admin
with step-up, audited BEFORE the write (`psa.instance.writes_toggle`). Nothing
else may set the key: instance create strips it from the submitted config and
credentials, and the adapter honours the registry row over whatever its merged
start config carries.

Every read here fails CLOSED: an unreadable registry means "off".
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Mapping, Optional

from apps.octo import paths

logger = logging.getLogger(__name__)

WRITES_ENABLED_KEY = "writes_enabled"
PSA_VENDOR_SLUGS: tuple[str, ...] = ("autotask",)


def writes_enabled_in(config: Optional[Mapping[str, Any]]) -> bool:
    """True only when `config[writes_enabled]` is the boolean True."""
    if not isinstance(config, Mapping):
        return False
    return config.get(WRITES_ENABLED_KEY) is True


def _instance_config(row: sqlite3.Row | tuple) -> dict[str, Any]:
    try:
        data = json.loads(row[0] or "{}")
    except (TypeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def instance_writes_enabled(instance_id: int) -> bool:
    """The persisted switch of ONE adapter instance. False when the instance
    does not exist, is disabled, or the registry cannot be read."""
    try:
        iid = int(instance_id)
    except (TypeError, ValueError):
        return False
    if iid <= 0:
        return False
    try:
        conn = sqlite3.connect(
            f"file:{paths.registry_db_path()}?mode=ro", uri=True, timeout=5.0)
        try:
            row = conn.execute(
                "SELECT instance_config_json FROM adapter_instances "
                " WHERE id = ? AND disabled_at IS NULL",
                (iid,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("[psa-writes] instance %s switch not read (%s): treated as OFF",
                       iid, type(exc).__name__)
        return False
    if row is None:
        return False
    return writes_enabled_in(_instance_config(row))


def psa_writes_enabled() -> bool:
    """Bundle-level answer for the console and the enqueue paths: True only
    when an ACTIVE PSA (Autotask) instance has its switch on."""
    marks = ",".join("?" * len(PSA_VENDOR_SLUGS))
    try:
        conn = sqlite3.connect(
            f"file:{paths.registry_db_path()}?mode=ro", uri=True, timeout=5.0)
        try:
            rows = conn.execute(
                "SELECT instance_config_json FROM adapter_instances "
                f" WHERE vendor_slug IN ({marks}) AND disabled_at IS NULL",
                PSA_VENDOR_SLUGS,
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("[psa-writes] switch not read (%s): treated as OFF",
                       type(exc).__name__)
        return False
    return any(writes_enabled_in(_instance_config(r)) for r in rows)
