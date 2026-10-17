"""Keys and rows for the archive-encryption tests. Every key pair is made by
the test itself (pyrage); fixture tenants are fictional (acme-corp / globex),
addresses RFC 5737, names RFC 2606."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

A, B = "acme-corp", "globex"


@dataclass
class KeyPair:
    """A test-generated age X25519 key pair: `public` (age1…), the identity
    FILE (0600, age-keygen layout) and the secret's text — only for asserting
    it never shows up anywhere."""
    public: str
    identity_path: Path
    secret: str


def keypair(tmp_path: Path, name: str = "operator") -> KeyPair:
    import pyrage

    ident = pyrage.x25519.Identity.generate()
    secret = str(ident)
    public = str(ident.to_public())
    path = tmp_path / f"{name}-identity.txt"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"# created: 2026-10-07T12:00:00Z\n# public key: {public}\n{secret}\n")
    os.chmod(path, 0o600)
    return KeyPair(public=public, identity_path=path, secret=secret)


def recipients_file(tmp_path: Path, *lines: str, mode: int = 0o600,
                    name: str = "archive-recipients.txt") -> Path:
    path = tmp_path / "secrets" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines))
    os.chmod(path, mode)
    return path


def row(i: int, day: str, domain: str = "printer.acme.example") -> dict:
    """A telemetry_raw row as the job archives it (every column the restore
    script reads)."""
    payload = json.dumps({"n": i, "d": domain})
    ts = f"{day}T10:{i % 60:02d}:00.000Z"
    return {
        "id": i, "received_at": ts, "ingested_at": ts, "source": "buoy:acme",
        "event_type": "pihole.query", "severity": "info", "source_host": "buoy-acme-1",
        "domain": domain, "device": "192.0.2.10", "device_name": "acme-laptop-07",
        "payload": payload, "payload_truncated": False,
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "origin_event_id": None,
    }


def leaked(secret: str, *texts: str) -> bool:
    """Does any text carry the secret key (whole, or its Bech32 body)?"""
    body = secret.split("1", 1)[1] if "1" in secret else secret
    needles = {secret, secret.lower(), body, body.lower(), body[:20], body[-20:]}
    return any(n and n in (t or "") for t in texts for n in needles)
