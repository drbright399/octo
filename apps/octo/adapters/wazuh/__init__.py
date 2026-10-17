"""Wazuh source adapter.

First concrete adapter under the Phase 2 framework. Implements the
`SourceAdapter` Protocol via `BaseSourceAdapter` from
`shared_adapter_contract`.

Two deploy modes:
  - bundled (default): adapter talks to the Wazuh manager that ships
    inside the OCTO bundle (compose-conditional siblings
    `wazuh-manager` + `wazuh-indexer`). Manager URL defaults to
    `http://wazuh-manager:55000` on the bundle's internal network.
  - external: adapter talks to an MSP-provided Wazuh manager URL +
    API key. Same adapter contract, different upstream address.

The mode is a deploy-time config decision (`OCTO_WAZUH_MODE=bundled|external`),
not a code fork. The wizard sets the env at first-deploy and stores the
per-instance config in registry.db via the framework's AdapterRegistry.
"""

from apps.octo.adapters.wazuh.adapter import WazuhSourceAdapter

# Reassign __module__ so the framework's discovery walker sees this
# adapter class as belonging to this package (its discovery filter
# rejects re-exports whose __module__ points at a submodule). Use the
# absolute dotted path rather than __name__ — under some test-import
# paths __name__ collapses to just "wazuh" which breaks the filter
# match against discover_adapters("apps.octo.adapters", ...).
WazuhSourceAdapter.__module__ = "apps.octo.adapters.wazuh"

__all__ = ["WazuhSourceAdapter"]
