"""An in-memory Autotask READ side for poller tests: `query_all` over fixture
rows, honouring what the poller sends — `gt` / `lte` on lastActivityDate,
MaxRecords as the page size — and the client's page cap (more pages than
`max_pages` raises AutotaskPageCapError, exactly like the real client).

Every call is recorded (entity, lo, hi, max_pages) so a test can see the
windows the catch-up read. A read by id (`eq` / `in` on another field: the
note backfill, the map refresh) is answered from the same rows and recorded
apart, in `lookups`. It has no write methods at all: a poller (or
anything else) that tried to write through it would fail loudly.
"""
from __future__ import annotations

import math
from typing import Any, Iterable, Optional

from apps.octo.adapters.autotask.client import AutotaskPageCapError
from apps.octo.adapters.autotask.poller import parse_activity_ts


class FakeAutotaskQuery:
    def __init__(
        self,
        tickets: Iterable[dict[str, Any]] = (),
        notes: Iterable[dict[str, Any]] = (),
    ) -> None:
        self.rows: dict[str, list[dict[str, Any]]] = {
            "Tickets": [dict(r) for r in tickets],
            "TicketNotes": [dict(r) for r in notes],
        }
        self.calls: list[tuple[str, Optional[str], Optional[str], int]] = []
        self.answered: list[bool] = []
        # Reads by id (`eq` / `in` on any other field — the note backfill, the
        # map refresh): (entity, field, values), kept apart from the windows.
        self.lookups: list[tuple[str, str, list[Any]]] = []
        # Raised (once each, in order) by the next lookups.
        self.lookup_errors: list[Exception] = []

    def _lookup(self, entity: str, filters: list[dict[str, Any]]) -> list[dict[str, Any]]:
        f = filters[0]
        field, op = f.get("field"), f.get("op")
        values = list(f["value"]) if op == "in" else [f["value"]]
        self.lookups.append((entity, str(field), values))
        if self.lookup_errors:
            raise self.lookup_errors.pop(0)
        return [dict(r) for r in self.rows.get(entity, []) if r.get(field) in values]

    def query_all(self, entity: str, body: dict[str, Any], *, max_pages: int = 10,
                  ) -> list[dict[str, Any]]:
        filters = list(body.get("filter", []))
        if filters and all(f.get("field") != "lastActivityDate" for f in filters):
            return self._lookup(entity, filters)
        lo = hi = None
        for f in filters:
            if f.get("field") != "lastActivityDate":
                continue
            if f.get("op") == "gt":
                lo = f["value"]
            elif f.get("op") == "lte":
                hi = f["value"]
        self.calls.append((entity, lo, hi, max_pages))
        lo_dt, hi_dt = parse_activity_ts(lo), parse_activity_ts(hi)
        out = []
        for row in self.rows.get(entity, []):
            at = parse_activity_ts(row.get("lastActivityDate"))
            if at is None:
                continue
            if lo_dt is not None and not at > lo_dt:
                continue
            if hi_dt is not None and not at <= hi_dt:
                continue
            out.append(dict(row))
        size = max(1, int(body.get("MaxRecords", 500)))
        if math.ceil(len(out) / size) > max_pages:
            self.answered.append(False)
            raise AutotaskPageCapError(f"{entity}/query: more than {max_pages} pages — not read")
        self.answered.append(True)
        return out

    def windows(self, entity: str) -> list[tuple[Optional[str], Optional[str]]]:
        return [(lo, hi) for e, lo, hi, _ in self.calls if e == entity]

    def read_windows(self, entity: str) -> list[tuple[Optional[str], Optional[str]]]:
        """The windows that were answered (not refused over the cap)."""
        return [(lo, hi) for (e, lo, hi, _), ok in zip(self.calls, self.answered)
                if e == entity and ok]
