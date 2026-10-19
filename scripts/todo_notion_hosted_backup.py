"""Hosted backup of the current Notion TODO data source, independent of Desktop.

Only ciphertext leaves the ephemeral producer. The retired Neon capture and its
guards are not invoked. A separate recovery run must prove actual restoration.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import uuid

from cryptography.hazmat.primitives import serialization

from pc24x7_todo_sealed import SealedBlocked, key_id
from todo_hosted_backup import (
    GitHubDraftTransport, HostedBlocked, already_uploaded, git_identity, verified_upload,
)
from todo_notion_sealed import encrypt_notion, inspect_notion_envelope
from todo_notion_snapshot import (
    NotionBlocked, NotionClient, collect_snapshot, snapshot_bytes, validate_snapshot,
)

SHA64 = re.compile(r"[0-9a-f]{64}\Z")


def require(ok, reason):
    if not ok:
        raise HostedBlocked(reason)


def _source_uuid(env, name):
    raw = env.get(name, "")
    try:
        parsed = uuid.UUID(raw)
    except (ValueError, TypeError, AttributeError):
        raise HostedBlocked("NOTION_SOURCE_REFERENCE_REQUIRED") from None
    require(raw.lower() in (str(parsed), parsed.hex), "NOTION_SOURCE_REFERENCE_INVALID")
    return str(parsed)


def recipient_preflight(env):
    raw = env.get("TODO_BACKUP_RECIPIENT_PEM_B64", "")
    require(0 < len(raw) <= 16384, "PUBLIC_RECIPIENT_REFERENCE_MISSING")
    try:
        pem = base64.b64decode(raw, validate=True)
        fingerprint = key_id(serialization.load_pem_public_key(pem))
    except Exception:
        raise HostedBlocked("RECIPIENT_INVALID") from None
    expected = env.get("TODO_BACKUP_RECIPIENT_SHA256", "")
    require(isinstance(expected, str) and SHA64.fullmatch(expected) and
            expected == fingerprint, "RECIPIENT_ATTESTATION_MISMATCH")
    require(bool(env.get("GITHUB_TOKEN")), "GITHUB_TOKEN_MISSING")
    return pem


def source_preflight(env):
    token = env.get("TODO_NOTION_READ_TOKEN", "")
    require(isinstance(token, str) and 20 <= len(token) <= 4096 and
            not any(character.isspace() for character in token),
            "NOTION_READ_TOKEN_REFERENCE_REQUIRED")
    minimum = env.get("TODO_NOTION_MIN_PAGES", "")
    require(isinstance(minimum, str) and re.fullmatch(r"[1-9][0-9]{0,3}", minimum),
            "NOTION_CARDINALITY_BASELINE_REQUIRED")
    return token, int(minimum)


def run(env, transport, *, client=None, now=None):
    commit = git_identity(env)
    pem = recipient_preflight(env)
    source_id = _source_uuid(env, "TODO_NOTION_DATA_SOURCE_ID")
    database_id = _source_uuid(env, "TODO_NOTION_DATABASE_ID")
    scope_hash = hashlib.sha256((database_id + "/" + source_id).encode("ascii")).hexdigest()[:16]
    instant = now or datetime.now(timezone.utc)
    require(isinstance(instant, datetime) and instant.tzinfo is not None,
            "NOTION_UTC_CLOCK_REQUIRED")
    tag = "todo-notion-backup-" + scope_hash + "-" + instant.astimezone(timezone.utc).strftime("%Y%m%d")
    name = tag + ".sealed"
    previous = already_uploaded(transport, name, tag, recipient_pem=pem,
                                inspector=inspect_notion_envelope)
    if previous is not None:
        # No plaintext is available on a producer replay: do not attest its source.
        return {
            **previous, "executor_sha": commit, "source_sha": None, "source_db": None,
            "source_kind": None, "capture_executed": False, "production_data_read": False,
            "configured_scope_hash": scope_hash, "decrypted_provenance_verified": False,
            "scheduled_execution": env.get("GITHUB_EVENT_NAME") == "schedule",
            "historical_neon_data_recovered": False, "backup_homologated": False
        }
    token, minimum = source_preflight(env)
    actual_client = client if client is not None else NotionClient(token)
    snapshot = collect_snapshot(
        actual_client, data_source_id=source_id, database_id=database_id,
        producer_sha=commit)
    payload = snapshot_bytes(snapshot)
    summary = validate_snapshot(snapshot)
    pages = summary["page_count"]
    roots = summary["root_page_count"]
    require(roots >= minimum, "NOTION_SOURCE_CARDINALITY_BELOW_BASELINE")
    manifest = {
        "schema_version": 1, "correlation_id": tag, "producer_sha": commit,
        "snapshot_sha256": hashlib.sha256(payload).hexdigest(),
        "content_sha256": snapshot["content_sha256"],
        "configured_scope_hash": scope_hash, "page_count": pages, "root_page_count": roots,
        "source_kind": "notion_data_source",
        "historical_neon_data_recovered": False,
        "canonical_cutover": False, "workers_started": False
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True, allow_nan=False).encode("utf-8")
    cipher = encrypt_notion(manifest_bytes, payload, pem)
    uploaded = verified_upload(transport, name, cipher, tag, commit,
                               recipient_pem=pem, inspector=inspect_notion_envelope)
    return {
        **uploaded, "executor_sha": commit, "source_sha": commit, "source_db": None,
        "source_kind": "notion_data_source", "page_count": pages, "root_page_count": roots,
        "capture_executed": True, "production_data_read": True,
        "configured_scope_hash": scope_hash, "decrypted_provenance_verified": False,
        "scheduled_execution": env.get("GITHUB_EVENT_NAME") == "schedule",
        "historical_neon_data_recovered": False, "backup_homologated": False
    }


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        env = dict(os.environ)
        result = run(env, GitHubDraftTransport(env.get("GITHUB_TOKEN", "")))
    except (HostedBlocked, SealedBlocked, NotionBlocked) as error:
        result = {"state": "blocked", "reason": str(error),
                  "backup_homologated": False, "canonical_cutover": False}
    except Exception:
        result = {"state": "blocked", "reason": "NOTION_HOSTED_UNEXPECTED_FAILURE",
                  "backup_homologated": False, "canonical_cutover": False}
    # No Notion IDs, page content, token, source URL, private key or unsealed payload.
    print(json.dumps(result, sort_keys=True))
    return 2 if result["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
