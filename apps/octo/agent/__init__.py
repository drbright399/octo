"""Autonomous data-plane agent — the 'octo' identity's runtime.

This package holds the autonomous Triage L1 worker (Task #119): the
deterministic heuristic engine, the background worker loop, and the
gated LLM-on-uncertain escalation.

Distinct from `apps/octo/api/routers/agent_query.py`, which is the
OPERATOR-triggered "Ask Octo" enrichment path. Both write into the same
per-tenant `agent_notes` table (agent_id='octo'); the autonomous path
marks its notes with query_kind='auto_enrich'.
"""
