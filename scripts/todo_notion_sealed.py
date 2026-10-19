"""Explicit encrypted Notion snapshot format; no source access or key provisioning.

Reuses the PostgreSQL envelope core with a distinct magic/OAEP label and keeps
the PostgreSQL V1 payload validator unchanged. Bytes are returned only after
authenticated decryption and snapshot validation. No keys are generated here.
"""
from __future__ import annotations

import re
import struct

from pc24x7_todo_sealed import (
    NOTION_MAGIC,
    MAX_DUMP,
    MAX_ENVELOPE,
    MAX_MANIFEST,
    SealedBlocked,
    decrypt_payload,
    digest,
    encrypt_payload,
    inspect_envelope_payload,
    require,
    strict_json,
)
from todo_notion_snapshot import validate_snapshot

MAGIC = NOTION_MAGIC
MAX_SNAPSHOT = MAX_DUMP


def validate_notion_payload(manifest: bytes, snapshot: bytes) -> dict:
    require(isinstance(manifest, bytes) and isinstance(snapshot, bytes) and
            0 < len(manifest) <= MAX_MANIFEST and 2 < len(snapshot) <= MAX_SNAPSHOT,
            "NOTION_PAYLOAD_SIZE_INVALID")
    metadata = strict_json(manifest)
    require(type(metadata.get("schema_version")) is int and metadata["schema_version"] == 1,
            "NOTION_MANIFEST_INVALID")
    require(isinstance(metadata.get("correlation_id"), str) and
            re.fullmatch(r"[A-Za-z0-9_.-]{3,96}", metadata["correlation_id"]) is not None,
            "CORRELATION_INVALID")
    require(isinstance(metadata.get("producer_sha"), str) and
            re.fullmatch(r"[0-9a-f]{40}", metadata["producer_sha"]) is not None,
            "NOTION_PRODUCER_SHA_INVALID")
    require(metadata.get("snapshot_sha256") == digest(snapshot), "NOTION_SNAPSHOT_DIGEST_MISMATCH")
    content = strict_json(snapshot)
    try:
        validate_snapshot(content)
    except Exception:
        # A collector/validator failure must never expose page content in a receipt.
        raise SealedBlocked("NOTION_SNAPSHOT_INVALID") from None
    require(content.get("producer_sha") == metadata["producer_sha"],
            "NOTION_PRODUCER_BINDING_MISMATCH")
    if "content_sha256" in metadata:
        require(metadata["content_sha256"] == content.get("content_sha256"),
                "NOTION_CONTENT_BINDING_MISMATCH")
    return metadata


def encrypt_notion(manifest: bytes, snapshot: bytes, recipient_pem: bytes) -> bytes:
    validate_notion_payload(manifest, snapshot)
    plain = struct.pack(">I", len(manifest)) + manifest + snapshot
    return encrypt_payload(plain, recipient_pem, magic=MAGIC)


def inspect_notion_envelope(envelope: bytes, recipient_pem: bytes | None = None) -> dict:
    """Structure/recipient only; no claim of AES-GCM authentication or key custody."""
    return inspect_envelope_payload(envelope, recipient_pem, magic=MAGIC)


def decrypt_notion(envelope: bytes, identity_pem: bytes) -> tuple[bytes, bytes]:
    plain = decrypt_payload(envelope, identity_pem, magic=MAGIC)
    require(len(plain) >= 4, "NOTION_PAYLOAD_SIZE_INVALID")
    mlen = struct.unpack(">I", plain[:4])[0]
    require(0 < mlen <= MAX_MANIFEST and 4 + mlen < len(plain), "NOTION_PAYLOAD_SIZE_INVALID")
    manifest, snapshot = plain[4:4+mlen], plain[4+mlen:]
    validate_notion_payload(manifest, snapshot)
    return manifest, snapshot
