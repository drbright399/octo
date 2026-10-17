"""Dev-only runtime tooling. Nothing in this package may run in
production: each entry point is gated on an explicit dev opt-in
(OCTO_DEV_SYNTHETIC) AND a dev data-root check. Per the internal rule
that dev conveniences never bypass auth, nothing here weakens the real
product surface — this is test-data generation, not an auth shortcut.
"""
