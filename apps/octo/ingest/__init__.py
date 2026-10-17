"""Ingest layer — canonical event → persistent storage + live event stream.

Adapters call `IngestSink.ingest(tenant_slug, source, event)`; the default
SQLite implementation writes the event into the per-client `events.db`,
extracts and upserts any IOC into `indicators.db`, and publishes to the
SSE broker so subscribed clients receive the new event in near-real-time.

The sink is an abstraction so future implementations (e.g., a Kafka
forwarder, an OpenSearch indexer) can replace the storage backend
without touching adapter code.
"""

from apps.octo.ingest.sink import IngestOutcome, IngestSink, SqliteIngestSink

__all__ = ["IngestOutcome", "IngestSink", "SqliteIngestSink"]
