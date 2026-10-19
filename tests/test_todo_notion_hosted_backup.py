"""Behavioral safety tests for the current-source hosted orchestration."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import todo_hosted_backup as legacy
import todo_notion_hosted_backup as hosted
from pc24x7_todo_sealed import SealedBlocked
from todo_notion_sealed import decrypt_notion
from notion_snapshot_fixture import SyntheticNotionClient, synthetic_snapshot
from notion_backup_test_support import (
    CountingClient, FakeDraftTransport, NeverClient, PRODUCER_SHA, hosted_env, key_material,
)

INSTANT = datetime(2026, 10, 19, 4, 43, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def keys():
    return key_material()


@pytest.fixture(autouse=True)
def linux_gate(monkeypatch):
    # Patch the module reference, not global os.name (Path must still work on Windows).
    monkeypatch.setattr(legacy, "os", SimpleNamespace(name="posix"))


def test_capture_encrypts_then_downloads_and_binds_producer(keys):
    identity, public = keys
    client = CountingClient(SyntheticNotionClient())
    store = FakeDraftTransport()
    receipt = hosted.run(hosted_env(public), store, client=client, now=INSTANT)
    assert receipt["state"] == "encrypted_draft_uploaded"
    assert receipt["root_page_count"] == 2 and receipt["page_count"] == 3
    assert receipt["capture_executed"] is True
    assert client.calls > 0 and store.uploads == 1 and store.downloads == 1
    asset = store.list_assets(receipt["release_id"])[0]
    ciphertext = store.readback(asset, 70 * 1024 * 1024)
    manifest_bytes, snapshot_bytes = decrypt_notion(ciphertext, identity)
    manifest, snapshot = json.loads(manifest_bytes), json.loads(snapshot_bytes)
    assert manifest["producer_sha"] == snapshot["producer_sha"] == PRODUCER_SHA
    assert manifest["snapshot_sha256"] == hashlib.sha256(snapshot_bytes).hexdigest()
    assert len(snapshot["content"]["pages"]) == 3
    assert receipt["ciphertext_sha256"] == hashlib.sha256(ciphertext).hexdigest()
    assert receipt["database_restore_verified"] is False
    assert receipt["offhost_custody_verified"] is False
    assert receipt["historical_neon_data_recovered"] is False
    assert receipt["backup_homologated"] is False
    assert receipt["ciphertext_authentication_verified"] is False
    assert receipt["decrypted_provenance_verified"] is False
    encoded_receipt = json.dumps(receipt)
    for private_value in (hosted_env(public)["TODO_NOTION_READ_TOKEN"],
                          hosted_env(public)["TODO_NOTION_DATABASE_ID"],
                          hosted_env(public)["TODO_NOTION_DATA_SOURCE_ID"]):
        assert private_value not in encoded_receipt


def test_replay_without_source_token_does_not_reconnect_or_upload(keys):
    _, public = keys
    store = FakeDraftTransport()
    env = hosted_env(public)
    first = hosted.run(env, store, client=SyntheticNotionClient(), now=INSTANT)
    env.pop("TODO_NOTION_READ_TOKEN")
    env["GITHUB_SHA"] = "b" * 40
    replay = hosted.run(env, store, client=NeverClient(), now=INSTANT)
    assert replay["state"] == "already_verified"
    assert replay["asset_id"] == first["asset_id"] and store.uploads == 1
    assert replay["capture_executed"] is False and replay["production_data_read"] is False
    assert replay["replay_without_source_access"] is True
    assert replay["executor_sha"] == "b" * 40
    assert replay["release_producer_sha"] == PRODUCER_SHA
    assert replay["source_sha"] is None and replay["source_kind"] is None
    assert replay["backup_homologated"] is False


@pytest.mark.parametrize("key,value", [
    ("GITHUB_ACTIONS", "false"),
    ("GITHUB_EVENT_NAME", "pull_request"),
    ("GITHUB_EVENT_NAME", "pull_request_target"),
    ("GITHUB_REF", "refs/heads/other"),
    ("GITHUB_REPOSITORY", "untrusted/fork"),
    ("GITHUB_SHA", "main"),
    ("TODO_BACKUP_CUSTODY_APPROVAL", ""),
    ("TODO_BACKUP_RECIPIENT_PEM_B64", ""),
    ("TODO_BACKUP_RECIPIENT_PEM_B64", "not-base64"),
    ("TODO_BACKUP_RECIPIENT_SHA256", "0" * 64),
    ("GITHUB_TOKEN", ""),
    ("TODO_NOTION_DATABASE_ID", "https://notion.so/private"),
    ("TODO_NOTION_DATA_SOURCE_ID", ""),
])
def test_invalid_identity_or_recipient_fails_before_storage(keys, key, value):
    _, public = keys
    env = hosted_env(public)
    env[key] = value
    store = FakeDraftTransport()
    with pytest.raises(hosted.HostedBlocked):
        hosted.run(env, store, client=NeverClient(), now=INSTANT)
    assert store.calls == []


@pytest.mark.parametrize("key,value", [
    ("TODO_NOTION_READ_TOKEN", ""),
    ("TODO_NOTION_READ_TOKEN", "a" * 19),
    ("TODO_NOTION_READ_TOKEN", "a" * 20 + "\n"),
    ("TODO_NOTION_MIN_PAGES", ""),
    ("TODO_NOTION_MIN_PAGES", "0"),
    ("TODO_NOTION_MIN_PAGES", "10000"),
    ("TODO_NOTION_MIN_PAGES", "-1"),
])
def test_missing_source_configuration_never_captures_or_uploads(keys, key, value):
    _, public = keys
    env = hosted_env(public)
    env[key] = value
    store = FakeDraftTransport()
    with pytest.raises(hosted.HostedBlocked):
        hosted.run(env, store, client=NeverClient(), now=INSTANT)
    assert store.calls == ["find_draft"] and store.uploads == 0


def test_minimum_cardinality_rejects_incomplete_scope(keys):
    _, public = keys
    env = hosted_env(public)
    # Three total pages include one child, which cannot replace a missing root task.
    env["TODO_NOTION_MIN_PAGES"] = "3"
    store = FakeDraftTransport()
    with pytest.raises(hosted.HostedBlocked, match="CARDINALITY_BELOW_BASELINE"):
        hosted.run(env, store, client=SyntheticNotionClient(), now=INSTANT)
    assert store.uploads == 0 and store.releases == []


def test_mutated_stored_ciphertext_blocks_replay_without_source(keys):
    _, public = keys
    store = FakeDraftTransport()
    receipt = hosted.run(hosted_env(public), store, client=SyntheticNotionClient(), now=INSTANT)
    payload = bytearray(store.payloads[receipt["asset_id"]])
    payload[-1] ^= 1
    store.payloads[receipt["asset_id"]] = bytes(payload)
    with pytest.raises(hosted.HostedBlocked, match="READBACK_MISMATCH"):
        hosted.run(hosted_env(public), store, client=NeverClient(), now=INSTANT)
    assert store.uploads == 1


def test_published_draft_blocks_replay(keys):
    _, public = keys
    store = FakeDraftTransport()
    hosted.run(hosted_env(public), store, client=SyntheticNotionClient(), now=INSTANT)
    store.releases[0]["draft"] = False
    with pytest.raises(hosted.HostedBlocked, match="DRAFT_RELEASE_REQUIRED"):
        hosted.run(hosted_env(public), store, client=NeverClient(), now=INSTANT)
    assert store.uploads == 1


def test_scheduled_receipt_does_not_claim_restoration_or_homologation(keys):
    _, public = keys
    env = hosted_env(public)
    env["GITHUB_EVENT_NAME"] = "schedule"
    receipt = hosted.run(env, FakeDraftTransport(), client=SyntheticNotionClient(), now=INSTANT)
    assert receipt["scheduled_execution"] is True
    assert receipt["database_restore_verified"] is False
    assert receipt["backup_homologated"] is False


def test_timezone_required_before_storage(keys):
    _, public = keys
    store = FakeDraftTransport()
    with pytest.raises(hosted.HostedBlocked, match="UTC_CLOCK_REQUIRED"):
        hosted.run(hosted_env(public), store, client=NeverClient(), now=datetime(2026, 10, 19))
    assert store.calls == []
