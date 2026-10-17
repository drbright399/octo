"""Alert ENRICHMENT for the operator view (v0.17.2, Rick's decision C) —
viewers keep today's neutral text.

  remote IPs   who owns the address (RDAP over HTTPS), its PTR (DNS-over-
               HTTPS to a PUBLIC resolver, by IP literal — the bundle's own
               resolver is never asked: it may be filtering, and the IOC
               must not leave through it) and whether that PTR is forward-
               confirmed; labels for known internet scanners and known
               vendor infrastructure. The remote address itself is NEVER
               contacted (`netintel` refuses a request whose target is the
               address being looked up). Cached in the registry
               (`enrichment_cache`, 7 days; a failure 1 hour), fetched in
               the BACKGROUND by one rate-limited worker (`worker`): a page
               never waits for the network — on a miss the raw text shows
               and the lookup is queued.
  UniFi IPS    direction, remote, owner / PTR / labels, the LOCAL device's
               name (the Datto device list, else the UniFi client name),
               "N× in 24 h" for (remote, local, signature) — `alerts`.
  Datto RMM    a deterministic one-line summary by alert class, the host,
               open / resolved, "N repeats since <date>" from Athena's own
               events (device + monitor signature) — `datto_summary`. No LLM.

`OCTO_IP_ENRICHMENT` = `on` (default) | `off`: off, nothing leaves the box
(the cached answers still show).
"""
