"""Autotask REST API client — zone resolution + auth + low-level HTTP.

Implements the two pieces P4-a needs end-to-end:

  1. `resolve_zone(username, *, http_get=...)` — unauthenticated GET to
     `webservices.autotask.net/atservicesrest/v1.0/zoneInformation` to
     discover which `webservices[n].autotask.net` host serves THIS
     Autotask tenant. Result is cached at the AdapterRegistry-instance
     level so each subsequent call hits the right zone directly.
     Re-resolve weekly or when zone-specific 4xx errors suggest a
     migration.

  2. `AutotaskClient.health_check()` — authenticated GET to
     `<zone>/V1.0/Companies/query?...&maxRecords=1`. Returns a 2xx
     when credentials + zone are both valid; this is what the
     smoke-test path on the adapter calls.

The HTTP transport is `requests`-backed by default but every entry
point accepts an `http_get` / `http_request` callable injection so
tests can stub the network without monkey-patching the requests
module globally.

Authentication uses the standard Autotask 3-header pattern:
  - `UserName`: the API user's generated Username (Key) — e-mail-shaped,
    but NOT a person's login e-mail (Autotask Resource flagged as API User)
  - `Secret`: the API-user password (rotatable)
  - `ApiIntegrationCode`: the integration's code (issued by Autotask)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

logger = logging.getLogger(__name__)


# Unauthenticated zone discovery endpoint. Same for every tenant in
# every region — the response tells us where to send everything else.
ZONE_DISCOVERY_URL = "https://webservices.autotask.net/atservicesrest/v1.0/zoneInformation"


class AutotaskClientError(Exception):
    """Base class for adapter-side Autotask client errors. Surfaces at
    the smoke-test boundary with operator-actionable messages. `status` is
    the HTTP status when Autotask answered (None: no answer)."""

    def __init__(self, message: str = "", *, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


class AutotaskZoneError(AutotaskClientError):
    """Zone discovery failed — username invalid, network unreachable,
    or Autotask returned an unexpected shape. Operator should verify
    the API-user email."""


class AutotaskAuthError(AutotaskClientError):
    """Authenticated request returned 401. UserName / Secret /
    IntegrationCode combination is wrong (or the API user is disabled).
    Operator should verify all three credentials."""


class AutotaskPageCapError(AutotaskClientError):
    """`query_all` stopped: the answer is longer than the page cap it was
    allowed to read. Nothing was returned, so the caller still knows nothing
    past its own cursor — the ticket poller splits the time window in half
    instead of advancing past rows it has not seen."""


class AutotaskForbiddenFieldError(AutotaskClientError):
    """A write payload carried a field Athena must never send (`contractID`:
    code invariant 1 of the PSA write design). Refused before any HTTP."""


class AutotaskRefusedError(AutotaskClientError):
    """The credentials work but this ENTITY cannot be read: the API user's
    security level does not include it (403, or an error naming a
    permission), or this Autotask does not offer it (404 / 405). A caller
    with a fallback (CompanyLocations → the company address only) uses it
    and says so."""


# Paging + batching for the bounded reads (`query_all`). Autotask answers at
# most 500 records a page and points at the next page with
# pageDetails.nextPageUrl; an `in` filter is kept to a modest list of ids.
MAX_RECORDS = 500
MAX_PAGES = 10
IN_BATCH = 200
_REFUSED_STATUSES = (403, 404, 405)
_REFUSED_WORDS = ("permission", "not authorized", "unauthorized", "security level",
                  "access denied", "not allowed")

COMPANY_ADDRESS_FIELDS = ("id", "companyName", "isActive", "address1", "address2", "city",
                          "state", "postalCode", "countryID", "lastTrackedModifiedDateTime")
LOCATION_ADDRESS_FIELDS = ("id", "companyID", "name", "isActive", "isPrimary", "address1",
                           "address2", "city", "state", "postalCode", "countryID")


@dataclass(frozen=True)
class AutotaskConfig:
    """Resolved configuration for a single Autotask integration instance."""

    username: str
    secret: str
    integration_code: str
    zone_url: str
    """Resolved base URL from zone discovery, ends in `/atservicesrest/v1.0/`."""
    timeout_seconds: float = 15.0
    verify_tls: bool = True


# ---------------------------------------------------------------------------
# HTTP injection shim
# ---------------------------------------------------------------------------

class HttpGetCallable(Protocol):
    """A callable that performs a GET — accepts (url, headers, timeout, verify)
    and returns an object with .status_code, .text, .json(). Matches the
    `requests.get` shape closely enough that the default impl uses requests
    directly, and tests can pass a stub."""

    def __call__(
        self, url: str, *, headers: Optional[dict[str, str]] = None,
        timeout: float = 15.0, verify: bool = True,
    ) -> Any: ...


def _default_http_get(
    url: str, *, headers: Optional[dict[str, str]] = None,
    timeout: float = 15.0, verify: bool = True,
) -> Any:
    """Default HTTP GET using the requests library. Lazy-imported so
    test stubs don't need requests installed."""
    import requests
    return requests.get(url, headers=headers, timeout=timeout, verify=verify)


# ---------------------------------------------------------------------------
# Zone resolution (unauthenticated)
# ---------------------------------------------------------------------------

def resolve_zone(
    username: str,
    *,
    http_get: HttpGetCallable = _default_http_get,
    timeout_seconds: float = 10.0,
    verify_tls: bool = True,
) -> str:
    """Discover which Autotask zone serves the given API user.

    `username` is an Autotask Resource email flagged as API User. Returns
    the resolved base URL (always ends in `/atservicesrest/v1.0/`).

    Raises `AutotaskZoneError` on non-2xx, malformed JSON, missing `url`
    field, or any network exception. Caller is expected to surface the
    error message to the operator unchanged — Autotask's error messages
    are reasonably actionable.

    Zone discovery is intentionally UNAUTHENTICATED (per Autotask docs)
    — this is the only call that runs without the 3-header credential
    bundle.
    """
    if not username or "@" not in username:
        raise AutotaskZoneError(
            f"username {username!r} doesn't look like an email — "
            "Autotask API users are always email-shaped"
        )
    url = f"{ZONE_DISCOVERY_URL}?user={username}"
    try:
        resp = http_get(url, timeout=timeout_seconds, verify=verify_tls)
    except Exception as exc:
        raise AutotaskZoneError(
            f"zone discovery network failure: {exc!r}"
        ) from exc

    status = getattr(resp, "status_code", None)
    if status != 200:
        body_preview = (getattr(resp, "text", "") or "")[:200]
        raise AutotaskZoneError(
            f"zone discovery returned HTTP {status}: {body_preview!r}"
        )

    try:
        payload = resp.json()
    except Exception as exc:
        raise AutotaskZoneError(
            f"zone discovery response was not JSON: {exc!r}"
        ) from exc

    zone_url = payload.get("url") if isinstance(payload, dict) else None
    if not isinstance(zone_url, str) or not zone_url.startswith("https://"):
        raise AutotaskZoneError(
            f"zone discovery payload missing usable 'url' field: "
            f"got {payload!r}"
        )
    # Autotask returns the trailing slash; normalize defensively.
    if not zone_url.endswith("/"):
        zone_url = zone_url + "/"
    return zone_url


# ---------------------------------------------------------------------------
# Send guard (PSA write design, section 2.5 invariant 1)
# ---------------------------------------------------------------------------

# Never sent on anything — tickets, charges, time entries. Autotask picks the
# company default contract; a free-text contract id from Athena is how time
# lands on the wrong (billable) contract. Compared case-insensitively.
FORBIDDEN_WRITE_FIELDS: frozenset[str] = frozenset({"contractid"})


def refuse_forbidden_fields(entity: str, payload: Any) -> None:
    """Raise AutotaskForbiddenFieldError when `payload` (a JSON object) has a
    forbidden key at its top level."""
    if not isinstance(payload, dict):
        return
    bad = sorted(k for k in payload if isinstance(k, str)
                 and k.lower() in FORBIDDEN_WRITE_FIELDS)
    if bad:
        raise AutotaskForbiddenFieldError(
            f"{entity} write refused: Athena never sends {', '.join(bad)}")


# ---------------------------------------------------------------------------
# Authenticated client
# ---------------------------------------------------------------------------

class AutotaskClient:
    """Authenticated REST client for a single Autotask integration.

    Holds the resolved config (zone + creds + tunables). Issues
    authenticated requests with the 3-header pattern. The P4-a slice
    only needs `health_check()`; P4-c1 + P4-c2 will add ticket-side
    methods (`query_tickets`, `query_ticket_notes`, `create_ticket`,
    `update_ticket`, etc.) against this same client.
    """

    def __init__(
        self,
        config: AutotaskConfig,
        *,
        http_request: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._cfg = config
        # Single HTTP entry point — `http_request(method, url, ...)`.
        # Default uses requests; tests inject stubs. Same shape across
        # GET / POST / PATCH so we don't proliferate getters.
        if http_request is None:
            import requests
            self._http = requests.request
        else:
            self._http = http_request

    @property
    def config(self) -> AutotaskConfig:
        return self._cfg

    def _auth_headers(self) -> dict[str, str]:
        """The 3-header credential bundle for every authenticated call."""
        return {
            "UserName": self._cfg.username,
            "Secret": self._cfg.secret,
            "ApiIntegrationCode": self._cfg.integration_code,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ----- Internal request helper -----

    def _query(self, entity: str, search_body: dict[str, Any]) -> dict[str, Any]:
        """Authenticated GET against `<zone>/V1.0/<entity>/query?search=...`.

        Single entry point so the auth headers + error handling stay
        consistent across health_check + ticket-side queries. Returns
        the parsed JSON envelope on 2xx; raises AutotaskAuthError on
        401 and AutotaskClientError on any other non-2xx / parse error
        / network failure.
        """
        search = json.dumps(search_body, separators=(",", ":"))
        url = f"{self._cfg.zone_url.rstrip('/')}/V1.0/{entity}/query?search={search}"
        return self._get_json(url, f"{entity}/query")

    def _get_json(self, url: str, what: str) -> dict[str, Any]:
        """One authenticated GET (a query, or the next page of one) → the
        JSON envelope. Errors carry the HTTP status (`status`)."""
        try:
            resp = self._http(
                "GET", url,
                headers=self._auth_headers(),
                timeout=self._cfg.timeout_seconds,
                verify=self._cfg.verify_tls,
            )
        except Exception as exc:
            raise AutotaskClientError(
                f"{what} network failure: {exc!r}"
            ) from exc

        status = getattr(resp, "status_code", None)
        if status == 401:
            raise AutotaskAuthError(
                "Autotask returned 401 — the Username must be the API user's "
                "Username (Key) (not a login e-mail), the Secret its Password "
                "(Secret), and the Integration code its API Tracking Identifier; "
                "the API user must be active",
                status=401,
            )
        if status is None or not 200 <= status < 300:
            body_preview = (getattr(resp, "text", "") or "")[:200]
            raise AutotaskClientError(
                f"{what} HTTP {status}: {body_preview!r}", status=status,
            )

        try:
            return resp.json()
        except Exception as exc:
            raise AutotaskClientError(
                f"{what} response was not JSON: {exc!r}", status=status,
            ) from exc

    def _same_zone(self, url: Any) -> bool:
        """A next-page URL is followed only on THIS zone's REST base: the
        credential headers never go anywhere else."""
        from urllib.parse import urlparse

        if not isinstance(url, str):
            return False
        zone, nxt = urlparse(self._cfg.zone_url), urlparse(url)
        return (nxt.scheme == "https" and nxt.netloc == zone.netloc
                and nxt.path.lower().startswith(zone.path.rstrip("/").lower() + "/"))

    def query_all(
        self, entity: str, search_body: dict[str, Any], *, max_pages: int = MAX_PAGES,
    ) -> list[dict[str, Any]]:
        """Every item of a query, following pageDetails.nextPageUrl (on this
        zone only) for at most `max_pages` pages. Never a silent partial
        answer: more pages than that, or a next page somewhere else, is an
        AutotaskClientError (a caller must not mistake a cut list for "the
        rest is gone"). The callers' filters keep reads small."""
        envelope = self._query(entity, search_body)
        items: list[dict[str, Any]] = []
        pages = 1
        while True:
            batch = envelope.get("items") if isinstance(envelope, dict) else None
            items.extend(i for i in (batch if isinstance(batch, list) else [])
                         if isinstance(i, dict))
            details = envelope.get("pageDetails") if isinstance(envelope, dict) else None
            nxt = details.get("nextPageUrl") if isinstance(details, dict) else None
            if not nxt:
                return items
            if not self._same_zone(nxt):
                raise AutotaskClientError(
                    f"{entity}/query: the next page is not on this zone — not followed")
            if pages >= max_pages:
                raise AutotaskPageCapError(
                    f"{entity}/query: more than {max_pages} pages — not read")
            envelope = self._get_json(nxt, f"{entity}/query (page {pages + 1})")
            pages += 1

    def _query_by_ids(
        self, entity: str, field: str, ids: list[int], fields: tuple[str, ...],
        *, active_only: bool,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        wanted = sorted({int(i) for i in ids if isinstance(i, int) and not isinstance(i, bool)})
        for start in range(0, len(wanted), IN_BATCH):
            chunk = wanted[start:start + IN_BATCH]
            filt: list[dict[str, Any]] = [{"op": "in", "field": field, "value": chunk}]
            if active_only:
                filt.append({"op": "eq", "field": "isActive", "value": True})
            out.extend(self.query_all(entity, {
                "filter": filt, "IncludeFields": list(fields), "MaxRecords": MAX_RECORDS,
            }))
        return out

    def query_companies(self, ids: list[int], *, active_only: bool = True) -> list[dict[str, Any]]:
        """These Companies (by id; the ACTIVE ones by default) with their
        address fields only — the location proposals read the mapped
        companies, nothing else."""
        return self._query_by_ids("Companies", "id", ids, COMPANY_ADDRESS_FIELDS,
                                  active_only=active_only)

    def query_company_locations(
        self, company_ids: list[int], *, active_only: bool = True,
    ) -> list[dict[str, Any]]:
        """The CompanyLocations of these companies (active by default).
        AutotaskRefusedError when this API user may not read them (or the
        entity is not offered): the caller falls back to the company
        address. Any other failure is an AutotaskClientError."""
        try:
            return self._query_by_ids("CompanyLocations", "companyID", company_ids,
                                      LOCATION_ADDRESS_FIELDS, active_only=active_only)
        except AutotaskAuthError:
            raise
        except AutotaskClientError as exc:
            text = str(exc).lower()
            if exc.status in _REFUSED_STATUSES or (
                    exc.status is not None and any(w in text for w in _REFUSED_WORDS)):
                raise AutotaskRefusedError(
                    f"CompanyLocations cannot be read (HTTP {exc.status})", status=exc.status,
                ) from None
            raise

    def health_check(self) -> dict[str, Any]:
        """Authenticated probe — `Companies/query?...&MaxRecords=1`.

        Returns the JSON envelope on success. Raises AutotaskAuthError
        on 401, AutotaskClientError on other failures.
        """
        return self._query("Companies", {
            "filter": [{"op": "gte", "field": "id", "value": 0}],
            "MaxRecords": 1,
        })

    def query_tickets(
        self,
        *,
        since_iso: Optional[str] = None,
        max_records: int = 500,
    ) -> dict[str, Any]:
        """Pull tickets with `lastActivityDate gt <since_iso>`. When
        `since_iso` is None, no time filter — returns up to MaxRecords
        most-recently-active tickets.

        Returns the full Autotask envelope `{items: [...],
        pageDetails: {...}}`. Caller is responsible for pagination via
        pageDetails (this v1 impl reads one page; the poller does
        cursor-based catch-up across cycles).
        """
        if since_iso is not None:
            filt = [{"op": "gt", "field": "lastActivityDate", "value": since_iso}]
        else:
            filt = [{"op": "gte", "field": "id", "value": 0}]
        return self._query("Tickets", {
            "filter": filt,
            "MaxRecords": max_records,
        })

    def query_ticket_notes(
        self,
        *,
        since_iso: Optional[str] = None,
        max_records: int = 500,
    ) -> dict[str, Any]:
        """TicketNotes companion to `query_tickets`. Same filter shape;
        the lastActivityDate field exists on TicketNotes too."""
        if since_iso is not None:
            filt = [{"op": "gt", "field": "lastActivityDate", "value": since_iso}]
        else:
            filt = [{"op": "gte", "field": "id", "value": 0}]
        return self._query("TicketNotes", {
            "filter": filt,
            "MaxRecords": max_records,
        })

    # -----------------------------------------------------------------------
    # P4-c2: write-back — create Ticket + TicketCharge on the Autotask side.
    #
    # POSTs are sent to {zone}/V1.0/{entity} with a JSON body matching
    # the Autotask Ticket / TicketCharge entity shape. On success
    # Autotask returns `{ "itemId": <new-id> }` — we surface that id
    # so the writeback worker can stamp it on tickets.autotask_id.
    #
    # The exact field map (Athena ticket → Autotask Ticket fields) is
    # finalized in apps/octo/adapters/autotask/writeback.py and
    # documented in the 2026-05-14 Autotask write-back hand-off (archived).
    # -----------------------------------------------------------------------

    def _post(self, entity: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Authenticated POST to `{zone}/V1.0/{entity}`. Symmetric error
        envelope with `_query`. The send guard runs first: a payload naming a
        forbidden field never leaves the process."""
        refuse_forbidden_fields(entity, payload)
        url = f"{self._cfg.zone_url.rstrip('/')}/V1.0/{entity}"
        try:
            resp = self._http(
                "POST", url,
                headers=self._auth_headers(),
                json=payload,
                timeout=self._cfg.timeout_seconds,
                verify=self._cfg.verify_tls,
            )
        except Exception as exc:
            raise AutotaskClientError(
                f"{entity} POST network failure: {exc!r}"
            ) from exc

        status = getattr(resp, "status_code", None)
        if status == 401:
            raise AutotaskAuthError(
                "Autotask returned 401 on POST — verify creds + API user "
                "has write permission on the target entity"
            )
        if status is None or not 200 <= status < 300:
            body_preview = (getattr(resp, "text", "") or "")[:400]
            raise AutotaskClientError(
                f"{entity} POST HTTP {status}: {body_preview!r}"
            )

        try:
            return resp.json()
        except Exception as exc:
            raise AutotaskClientError(
                f"{entity} POST response was not JSON: {exc!r}"
            ) from exc

    def create_ticket(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST a new Ticket. `payload` is the full Autotask Ticket
        entity shape — at minimum `accountID`, `title`, `description`,
        `status`, `priority`, `queueID`. The writeback worker assembles
        the payload from the Athena ticket + the tenant↔company map +
        the picklist cache.

        Returns the Autotask response envelope. The new ticket id is at
        `resp["itemId"]` per Autotask REST convention.
        """
        return self._post("Tickets", payload)

    def create_ticket_charge(self, payload: dict[str, Any]) -> dict[str, Any]:
        """POST a new TicketCharge tied to a ticket. `payload` must
        include `ticketID`, `name`, `unitPrice`, `quantity`, optional
        `billingCodeID`, etc. Mirrors the Athena ticket_charges row.
        """
        return self._post("TicketCharges", payload)
