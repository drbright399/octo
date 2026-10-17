"""Proposals — an integration PROPOSES, an operator CONFIRMS (registry 043).

The generic mechanism, first used for Autotask addresses proposed as Fleet
SITE locations:

  store.py          the `proposals` table: list / get, the generic sync (what
                    an integration currently says → new proposals, superseded
                    ones, nothing re-proposed that was rejected while the
                    source data is the same) and the decisions (confirmed /
                    rejected, with who and why)
  address.py        US postal addresses: cleaning, state abbreviations, the
                    suite / unit kept apart (in the label, never in the
                    geocoder's query), a comparison key ("300 W 5th St" ==
                    "300 W. 5th Street")
  site_location.py  Autotask → site-location proposals: the candidates (the
                    company address + its active CompanyLocations, mapped
                    ACTIVE companies only), which site each one is for, the
                    warnings (shared address, incomplete, far from the
                    console, a pin already set), the refresh (on demand and
                    daily from the Autotask poller — never a geocoder call),
                    the on-demand lookup and what a confirm writes

Rules every kind keeps:
  * nothing a proposal says is in force until an operator (admin+) confirms
    it — audited BEFORE the write, with a reason; a rejection carries one too;
  * a rejected proposal is never proposed again while the source data is the
    same (`source_hash`); a CHANGE supersedes the open proposal and proposes
    the new data with the old one alongside — whatever is in force stays
    until the new one is confirmed;
  * client users (viewers) never see a proposal; the API is admin+ and scoped
    (a proposal of a tenant out of scope is the same 404 as none).
"""
