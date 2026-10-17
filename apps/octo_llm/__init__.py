"""octo-llm — Layer 2 LLM sibling container for the OCTO bundle.

The OCTO bundle's optional intelligence-augmentation layer. octo-llm
provides structured-in / structured-out endpoints that the
deterministic octo-agent (in octo-core) can call to enrich heuristic
notes with model-generated context, suggest triage severities, and
similar narrow, well-shaped tasks.

octo-llm is **never load-bearing** — per the M5/§11.5 contract,
octo-core must fall back cleanly to heuristic-only behavior when
octo-llm is unhealthy, slow, or disabled. See the internal design
notes on keeping Athena/OCTO self-contained and on the noise-dismissal
north star.

API surface (domain-specific, not OpenAI chat-compatible):

  GET  /v1/healthz         - liveness + model status
  POST /v1/enrich-note     - augment a heuristic agent_note
  POST /v1/triage-event    - suggest severity + rationale for an event

The endpoints accept only Pydantic-validated structured input and
return only Pydantic-validated structured output. This enforces the
§11.1 v2 axis at the API boundary: the LLM never sees a raw
`messages: [...]` chat array, and callers never receive freeform
text outside the documented response shape.

Slice 1 (this commit): scaffolding only - endpoints return canned
"stub" responses with model_version="stub-v0". No model weights, no
llama.cpp. Slice 2 wires the real Granite 3B Q4 GGUF.

Module structure:
  - server.py     FastAPI app factory + endpoint glue.
  - config.py     Settings: stub-mode flag, model path, threads, etc.
  - models.py     Pydantic request/response shapes.
  - inference.py  Pluggable inference backend interface. Slice 1
                  ships only the StubBackend; Slice 2 adds
                  LlamaCppBackend.
  - prompts/      Templated prompt files (one per endpoint).
"""
