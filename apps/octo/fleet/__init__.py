"""Fleet v2 — the site-centric fleet view and the ISP-outage correlation.

  state.py       the worst-state calculator: one verdict per LAYER (network,
                 security, endpoints, buoy) and the site's worst (the pin
                 colour) with its reason; stale data is UNKNOWN, never ok;
                 NOTICE (the quiet tier) is seen but never colours the pin
  locations.py   the manual SITE override (registry 042, locked pins), the
                 manual per-tenant fallback (041) and the precedence: site
                 override > UniFi console location (a multi-site console
                 only when it is one tenant's alone) > tenant fallback > no pin
  geocode.py     the on-demand address lookup (US Census, the typed address
                 only, nothing stored; OCTO_GEOCODER=off turns it off)
  sources.py     readers over what the pollers ALREADY store (no vendor call
                 on a page load): UniFi fleet health, IPS buckets, NextDNS
                 protection + threat roll-ups, RocketCyber open incidents,
                 Datto inventory, entity site links, buoy heartbeats
  build.py       the whole fleet model, cached and built under a time bound;
                 the API filters it per caller (role + scope)
  isp_outage.py  the correlator the UniFi poller runs after every fleet poll:
                 >= N failure points (consoles / WAN addresses / sites) on
                 ONE ISP ASN losing WAN within a window → ONE
                 `fleet.isp_outage` signal (HIGH, OCSF Incident Finding) in
                 the operator's internal tenant, the per-site WAN alerts
                 grouped under it, closed with a note on recovery
"""
