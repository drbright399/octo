# octo-llm

The OCTO bundle's **optional** Layer 2 LLM sibling. Provides
structured-only `/v1/enrich-note` and `/v1/triage-event` endpoints
that the deterministic octo-agent (in octo-core) can call to augment
heuristic output with model-generated context.

## Critical invariant

octo-llm is **never load-bearing**. octo-core falls back to
heuristic-only behavior when this service is unhealthy, slow,
disabled, or absent. Test this regression on every change.

See:
- The sanitized-pool safety-envelope design, §11.5
  (`docs/design/sanitized-pool/m1-m9-safety-envelope.md`; not in the public
  copy)
- The reviewer's "LLM is value-add, not load-bearing" finding from
  the 2026-05-21 v2 round

## Slice status

| Slice | Status | Contents |
|------:|:-------|:---------|
| 1     | ✅ DONE | API scaffold + stub backend + tests + Dockerfile |
| 2     | pending | llama-cpp + Granite 3B Q4 GGUF wiring |
| 3     | pending | Notes UI surfaces |
| 4     | pending | octo-core ↔ octo-llm wiring + audit row per call |

## API

All endpoints are domain-specific (NOT OpenAI chat-compatible). The
LLM never sees a raw `messages: [...]` array, and callers never get
freeform text outside the documented response fields.

| Method | Path | Purpose |
|--------|------|---------|
| GET    | `/v1/healthz`      | Liveness + model readiness |
| POST   | `/v1/enrich-note`  | Augment a heuristic agent_note |
| POST   | `/v1/triage-event` | Suggest severity + rationale for an event |

Pydantic models in `models.py` define the precise request / response
shapes. Validation errors return HTTP 400 with the `ErrorResponse`
shape: `{"error": "validation_error", "detail": "<concise>"}`.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `OCTO_LLM_BACKEND`                  | `stub`        | `stub` \| `llama-cpp` (slice 2+) |
| `OCTO_LLM_MODEL_PATH`               | `/var/lib/octo-llm/models/granite-3b-q4.gguf` | GGUF model path |
| `OCTO_LLM_THREADS`                  | `-1`          | `-1` = all cores |
| `OCTO_LLM_CONTEXT_TOKENS`           | `4096`        | Model context window cap |
| `OCTO_LLM_MAX_OUTPUT_TOKENS`        | `512`         | Per-request generation cap |
| `OCTO_LLM_REQUEST_TIMEOUT_SECONDS`  | `30.0`        | Hard wall-clock per request |

## Running locally (slice 1, stub mode)

From the repo root:

```bash
PYTHONPATH=. \
  ../athena-2026-04-26-cc/packages/.venv/bin/python -m uvicorn \
  apps.octo_llm.server:app --port 8101 --reload
```

Smoke:

```bash
curl -s localhost:8101/v1/healthz | python -m json.tool
curl -s -X POST localhost:8101/v1/enrich-note \
  -H 'content-type: application/json' \
  -d '{
        "ref_kind": "event",
        "ref_id": 1,
        "heuristic_note": "Three SSH brute-force attempts in 30s",
        "signals": ["matched_rule:brute-force-ssh"],
        "tenant_scope_slug": "acme"
      }' | python -m json.tool
```

## Demo: end-to-end enrichment in the dev pair (slice 6)

Three steps gets you live LLM enrichment in the dashboard:

```bash
# 1. Start the full pair WITH octo-llm sibling on :8101
OCTO_LLM_DEV=1 ./scripts/dev.sh

# 2. In a second terminal, flip the gates + grant the dev operator
./scripts/dev_enable_llm.sh

# 3. Open the dashboard, click any alert, click "Ask Octo"
#    → you'll see a stub enrichment land in the drawer with prefix
#       "[stub-v0 ask:<kind>] ..."
```

The stub backend echoes the heuristic note with a per-query-kind
prefix. To swap in a real model (Granite 3B Q4), see slice 2
(in progress; needs `llama-cpp-python` + weights).

## Docker

```bash
docker build -f apps/octo_llm/Dockerfile -t athena/octo-llm:v0.1 .
docker run --rm -p 8101:8101 athena/octo-llm:v0.1
```

## Tests

```bash
PYTHONPATH=. <venv>/bin/python -m pytest apps/octo_llm/tests/ -v
```

Slice 1 ships 21 tests covering the API contract, validation
boundaries, backend-selection error path, and the
"messages payload is silently ignored" defense in depth.
