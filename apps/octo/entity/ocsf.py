"""A stored answer as an OCSF ENRICHMENT (design 8.2) — the event itself is
never rewritten (payload sha and audit chain depend on it); the answer is
added beside it:

  enrichments[] = {name: "athena.entity_resolution", value: <site / device
                   token>, type: "site" | "device", provider:
                   "athena-resolver/<version>", data: {tier, score, site,
                   basis, candidates (count), chain_ref, flags}}

The observed `src_endpoint.ip` stays as the vendor saw it. A device appears
here only as its TOKEN; `device.*` would be set only at strong / exact —
slice 1 never reaches that for a device (fakeable keys cap below it).
"""
from __future__ import annotations

import json
from typing import Any

from apps.octo.entity.resolver import RESOLVER_VERSION


def enrichment(resolution: dict[str, Any]) -> dict[str, Any]:
    try:
        flags = json.loads(resolution.get("flags") or "[]")
    except ValueError:
        flags = []
    device = resolution.get("device_ref")
    return {
        "name": "athena.entity_resolution",
        "value": device or resolution.get("site_id") or "unresolved",
        "type": "device" if device else "site",
        "provider": f"athena-resolver/{resolution.get('resolver_version') or RESOLVER_VERSION}",
        "data": {
            "tier": resolution.get("tier"), "score": resolution.get("score"),
            "site": {"uid": resolution.get("site_id"), "basis": resolution.get("site_basis"),
                     "score": resolution.get("site_score"), "tier": resolution.get("site_tier")},
            "candidates": resolution.get("n_candidates"),
            "chain_ref": resolution.get("res_id"),
            "status": resolution.get("status"),
            "flags": flags,
        },
    }
