# Architecture decision records

Two numbering series appear in this repository. The number of digits tells
them apart; always write a citation with the right number of digits.

- **ADR-NNNN (four digits)** is a record in this directory.
- **ADR-NNN (three digits)** is one of the earlier design notes (ADR-003 to
  ADR-007, listed below). Those notes are kept outside the repository; code
  and package docs cite them by number and section, never by a file path.

ADR-0003 and ADR-003, and ADR-0004 and ADR-004, are therefore different
documents. The four-digit series skips ADR-0006 and ADR-0007 so that no
later record shares a number with a design note; the next new record is
**ADR-0008**.

## Records in this directory

| ADR | Title | Status | Cited from |
|---|---|---|---|
| ADR-0001 | [Fleet map basemap: MapLibre GL JS + self-hosted PMTiles](0001-fleet-map-basemap.md) | accepted 2026-05-19 | `scripts/fetch_dev_tiles.sh` |
| ADR-0002 | [OCTO is the data substrate; the orchestrator is the operator AI](0002-octo-data-substrate.md) | accepted 2026-09-09 | `docs/architecture.md`, `apps/octo/README.md`, the roadmap |
| ADR-0003 | [A new bundle host becomes the OCTO host: fresh bundle build, the legacy host frozen as an archive](0003-fresh-bundle-build-on-new-host.md) | accepted 2026-09-12 | `apps/octo/api/routers/ingest.py` and its tests (the client-token ingest endpoint the fresh build required), `scripts/mint_client_token.py` |
| ADR-0004 | [Evolve the existing repo in place, no V2 repo](0004-evolve-repo-in-place.md) | accepted 2026-09-16 | — |

**ADR-0005**, the productized seam (private first boot and a one-time setup
code), is proposed and has no file yet; it gets one, and a row above, once
it is accepted. The roadmap cites it by that number.

## Design notes cited in code (not in this repository)

| Note | Subject | Where the decision shows in this repository |
|---|---|---|
| ADR-003 | Athena / OCTO boundary: data plane vs control plane, tenant isolation, bearer sessions from the console's auth core | `docs/architecture.md`; `apps/octo/framework/bridge_router.py`; `apps/octo_llm/models.py` |
| ADR-004 | The bridge as a public, versioned interface (§ "Five mandatory invariants") | `packages/shared-bridge/` (README, `invariants.py`); `apps/octo/framework/bridge_server.py` |
| ADR-005 | Source-adapter contract (§ "The contract", "Lifecycle states", "Directory layout") | `packages/shared-adapter-contract/`; `apps/octo/framework/` (registry, lifecycle, discovery) |
| ADR-006 | Widget framework (§ "Widget Registry", "Layout persistence", "System widgets") | `packages/shared-widget-contract/`; `apps/athena/framework/` (widget registry, layouts) |
| ADR-007 | Action-adapter framework (planned, never written) | review notes only |

The packages' READMEs and docstrings restate each contract and its invariants,
so the code can be read without the notes.

## Adding a record

Name the file `NNNN-short-title.md` with the next free four-digit number (see
above), and give it a Status, a Decision maker and, where it builds on another
record, a "Builds on" line. Name hosts by role ("the bundle host", "the legacy
host"), never by a real host name, hardware model, address or port: records
are written to be published. A record goes into the public copy once it is
listed, by name, in `ops/public/allowlist.txt`.
