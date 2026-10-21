"""Notion codec contracts: real cryptography, synthetic snapshots, no remote service."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import pc24x7_todo_sealed as pg
import todo_notion_sealed as notion
from todo_notion_snapshot import snapshot_bytes
from notion_snapshot_fixture import synthetic_snapshot
from test_todo_hosted_backup import FakeRelease, b as storage

PRODUCER = "a" * 40


@pytest.fixture(scope="module")
def identity():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(scope="module")
def keys(identity):
    return (
        identity.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        identity.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
    )


@pytest.fixture(scope="module")
def other_public():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def payload():
    snapshot = synthetic_snapshot(producer_sha=PRODUCER)
    data = snapshot_bytes(snapshot)
    manifest = pg.canonical({
        "schema_version": 1,
        "correlation_id": "notion-codec-synthetic",
        "snapshot_sha256": hashlib.sha256(data).hexdigest(),
        "producer_sha": PRODUCER,
        "content_sha256": snapshot["content_sha256"],
    })
    return manifest, data


def pg_payload():
    # A wire-format fixture only. This is explicitly not a real PostgreSQL dump.
    archive = b"PGDMP-synthetic-v1-compatibility-control"
    manifest = pg.canonical({
        "schema_version": 1, "correlation_id": "pg-v1-synthetic",
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
    })
    return manifest, archive


def test_notion_roundtrip_has_explicit_format_and_shared_recipient(keys):
    manifest, snapshot = payload()
    envelope = notion.encrypt_notion(manifest, snapshot, keys[0])
    assert envelope.startswith(b"TODO-NOTION-SEALED-V1\0")
    assert not envelope.startswith(pg.MAGIC)
    assert snapshot not in envelope and b"PRIVATE KEY" not in envelope
    inspected = notion.inspect_notion_envelope(envelope, keys[0])
    assert inspected["header"]["recipient"] == pg.key_id(
        serialization.load_pem_public_key(keys[0]))
    assert len(inspected["wrapped"]) == 384
    assert notion.decrypt_notion(envelope, keys[1]) == (manifest, snapshot)
    assert notion.encrypt_notion(manifest, snapshot, keys[0]) != envelope


def test_formats_cannot_be_mixed_or_relabelled(keys):
    manifest, snapshot = payload()
    notion_cipher = notion.encrypt_notion(manifest, snapshot, keys[0])
    pg_manifest, archive = pg_payload()
    pg_cipher = pg.encrypt(pg_manifest, archive, keys[0])
    for reader, cipher in (
        (pg.inspect_envelope, notion_cipher),
        (notion.inspect_notion_envelope, pg_cipher),
    ):
        with pytest.raises(pg.SealedBlocked, match="ENVELOPE_INVALID"):
            reader(cipher, keys[0])
    with pytest.raises(pg.SealedBlocked, match="ENVELOPE_INVALID"):
        pg.decrypt(notion_cipher, keys[1])
    with pytest.raises(pg.SealedBlocked, match="ENVELOPE_INVALID"):
        notion.decrypt_notion(pg_cipher, keys[1])
    # Header relabelling passes framing but must fail the bound OAEP/AEAD format.
    relabelled = pg.MAGIC + notion_cipher[len(notion.MAGIC):]
    assert pg.inspect_envelope(relabelled, keys[0])["header"]["recipient"]
    with pytest.raises(pg.SealedBlocked, match="AUTHENTICATION_FAILED"):
        pg.decrypt(relabelled, keys[1])


def test_postgres_validator_still_rejects_json_payload(keys):
    _, snapshot = payload()
    manifest = pg.canonical({
        "schema_version": 1, "correlation_id": "not-a-pg-dump",
        "archive_sha256": hashlib.sha256(snapshot).hexdigest(),
    })
    with pytest.raises(pg.SealedBlocked, match="ARCHIVE_INTEGRITY_FAILED"):
        pg.encrypt(manifest, snapshot, keys[0])


@pytest.mark.parametrize("field,value,reason", [
    ("schema_version", True, "NOTION_MANIFEST_INVALID"),
    ("schema_version", 1.0, "NOTION_MANIFEST_INVALID"),
    ("correlation_id", "../unsafe", "CORRELATION_INVALID"),
    ("producer_sha", "b" * 40, "NOTION_PRODUCER_BINDING_MISMATCH"),
    ("producer_sha", "main", "NOTION_PRODUCER_SHA_INVALID"),
    ("snapshot_sha256", "b" * 64, "NOTION_SNAPSHOT_DIGEST_MISMATCH"),
    ("content_sha256", "b" * 64, "NOTION_CONTENT_BINDING_MISMATCH"),
])
def test_manifest_binding_is_checked_before_encryption(keys, field, value, reason):
    manifest, snapshot = payload()
    changed = json.loads(manifest)
    changed[field] = value
    with pytest.raises(pg.SealedBlocked, match=reason):
        notion.encrypt_notion(pg.canonical(changed), snapshot, keys[0])


def test_invalid_snapshot_cannot_be_sealed_even_with_matching_outer_digest(keys):
    manifest, snapshot = payload()
    altered = json.loads(snapshot)
    altered["schema_version"] = "unsupported-snapshot-format"
    raw = pg.canonical(altered)
    metadata = json.loads(manifest)
    metadata["snapshot_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(pg.SealedBlocked, match="NOTION_SNAPSHOT_INVALID"):
        notion.encrypt_notion(pg.canonical(metadata), raw, keys[0])


def test_duplicate_manifest_keys_are_rejected(keys):
    manifest, snapshot = payload()
    duplicate = manifest.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
    assert duplicate != manifest
    with pytest.raises(pg.SealedBlocked, match="JSON_DUPLICATE_KEY"):
        notion.encrypt_notion(duplicate, snapshot, keys[0])


def test_decryption_validates_authenticated_payload_before_returning_bytes(keys):
    manifest, snapshot = payload()
    metadata = json.loads(manifest)
    metadata["snapshot_sha256"] = "0" * 64
    bad_manifest = pg.canonical(metadata)
    # Deliberately bypass the format wrapper to test the validator on decryption.
    wire = pg.encrypt_payload(
        struct.pack(">I", len(bad_manifest)) + bad_manifest + snapshot,
        keys[0], magic=notion.MAGIC,
    )
    with pytest.raises(pg.SealedBlocked, match="NOTION_SNAPSHOT_DIGEST_MISMATCH"):
        notion.decrypt_notion(wire, keys[1])


def test_corruption_is_not_authenticated_by_header_inspection(keys):
    manifest, snapshot = payload()
    cipher = notion.encrypt_notion(manifest, snapshot, keys[0])
    altered = cipher[:-1] + bytes([cipher[-1] ^ 1])
    assert notion.inspect_notion_envelope(altered, keys[0])["header"]["recipient"]
    with pytest.raises(pg.SealedBlocked, match="AUTHENTICATION_FAILED"):
        notion.decrypt_notion(altered, keys[1])


def test_wrong_recipient_is_rejected_before_storage(keys, other_public):
    manifest, snapshot = payload()
    cipher = notion.encrypt_notion(manifest, snapshot, keys[0])
    dest = FakeRelease()
    with pytest.raises(pg.SealedBlocked, match="RECIPIENT_MISMATCH"):
        storage.verified_upload(
            dest, "notion-synthetic.sealed", cipher, "notion-synthetic", PRODUCER,
            recipient_pem=other_public, inspector=notion.inspect_notion_envelope,
        )
    assert dest.calls == []


@pytest.mark.parametrize("cut", [0, 10, 50, 250])
def test_truncated_notion_envelope_is_rejected(keys, cut):
    manifest, snapshot = payload()
    envelope = notion.encrypt_notion(manifest, snapshot, keys[0])
    with pytest.raises(pg.SealedBlocked):
        notion.decrypt_notion(envelope[:cut], keys[1])


def test_unknown_envelope_format_is_never_accepted(keys):
    with pytest.raises(pg.SealedBlocked, match="ENVELOPE_FORMAT_INVALID"):
        pg.encrypt_payload(b"opaque", keys[0], magic=b"UNKNOWN-V1\0")


def test_storage_requires_explicit_notion_inspector_and_replays_same_asset(keys):
    manifest, snapshot = payload()
    cipher = notion.encrypt_notion(manifest, snapshot, keys[0])
    dest = FakeRelease()
    name, tag = "todo-notion-synthetic.sealed", "todo-notion-synthetic"
    with pytest.raises(storage.HostedBlocked, match="CIPHERTEXT_FORMAT_INVALID"):
        storage.verified_upload(dest, name, cipher, tag, PRODUCER, recipient_pem=keys[0])
    assert dest.calls == []
    first = storage.verified_upload(
        dest, name, cipher, tag, PRODUCER,
        recipient_pem=keys[0], inspector=notion.inspect_notion_envelope,
    )
    repeated = storage.already_uploaded(
        dest, name, tag, recipient_pem=keys[0], inspector=notion.inspect_notion_envelope,
    )
    assert first["state"] == "encrypted_draft_uploaded"
    assert repeated["state"] == "already_verified"
    assert repeated["release_producer_sha"] == PRODUCER
    assert repeated["asset_id"] == first["asset_id"]
    assert repeated["ciphertext_sha256"] == hashlib.sha256(cipher).hexdigest()
    assert dest.calls.count("upload") == 1
    assert dest.calls[-1] == "get_release"
    for receipt in (first, repeated):
        assert receipt["recipient_matched"] and receipt["envelope_structure_verified"]
        assert not receipt["ciphertext_authentication_verified"]
        assert not receipt["database_restore_verified"]
        assert not receipt["offhost_custody_verified"] and not receipt["cutover_ready"]
    with pytest.raises(storage.HostedBlocked, match="OFFSITE_CIPHERTEXT_READBACK_MISMATCH"):
        storage.already_uploaded(dest, name, tag, recipient_pem=keys[0])
    assert dest.calls.count("upload") == 1


def test_notion_replay_detects_rotated_recipient_and_remote_corruption(keys, other_public):
    manifest, snapshot = payload()
    cipher = notion.encrypt_notion(manifest, snapshot, keys[0])
    dest = FakeRelease()
    name, tag = "notion-replay-control.sealed", "notion-replay-control"
    storage.verified_upload(dest, name, cipher, tag, PRODUCER,
                            recipient_pem=keys[0], inspector=notion.inspect_notion_envelope)
    with pytest.raises(pg.SealedBlocked, match="RECIPIENT_MISMATCH"):
        storage.already_uploaded(dest, name, tag,
                                 recipient_pem=other_public, inspector=notion.inspect_notion_envelope)
    dest.corrupt = True
    with pytest.raises(storage.HostedBlocked, match="OFFSITE_CIPHERTEXT_READBACK_MISMATCH"):
        storage.already_uploaded(dest, name, tag,
                                 recipient_pem=keys[0], inspector=notion.inspect_notion_envelope)
    assert dest.calls.count("upload") == 1


def test_storage_does_not_claim_authentication_for_replaced_ciphertext(keys):
    manifest, snapshot = payload()
    cipher = notion.encrypt_notion(manifest, snapshot, keys[0])
    dest = FakeRelease()
    name, tag = "notion-untrusted-replacement.sealed", "notion-untrusted-replacement"
    storage.verified_upload(dest, name, cipher, tag, PRODUCER,
                            recipient_pem=keys[0], inspector=notion.inspect_notion_envelope)
    altered = cipher[:-1] + bytes([cipher[-1] ^ 1])
    asset = dict(dest.assets[name][0])
    asset["digest"] = "sha256:" + hashlib.sha256(altered).hexdigest()
    dest.assets[name] = (asset, altered)
    receipt = storage.already_uploaded(dest, name, tag,
                                      recipient_pem=keys[0], inspector=notion.inspect_notion_envelope)
    assert receipt["ciphertext_authentication_verified"] is False
    with pytest.raises(pg.SealedBlocked, match="AUTHENTICATION_FAILED"):
        notion.decrypt_notion(altered, keys[1])


def test_pg_v1_wire_compatibility_with_independent_pre_refactor_encoding(keys, identity):
    """Check the published V1 framing/label in both directions, outside shared helpers."""
    magic = b"TODO-PG-SEALED-V1\0"
    manifest, archive = pg_payload()
    public = identity.public_key()
    recipient = hashlib.sha256(public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                       algorithm=hashes.SHA256(), label=magic)
    key = AESGCM.generate_key(bit_length=256)
    header = json.dumps({
        "v": 1, "recipient": recipient,
        "wrapped": base64.b64encode(public.encrypt(key, oaep)).decode("ascii"),
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    aad = magic + struct.pack(">I", len(header)) + header
    plain = struct.pack(">I", len(manifest)) + manifest + archive
    nonce = os.urandom(12)
    previous_wire = aad + nonce + AESGCM(key).encrypt(nonce, plain, aad)
    assert pg.decrypt(previous_wire, keys[1]) == (manifest, archive)

    current_wire = pg.encrypt(manifest, archive, keys[0])
    assert current_wire.startswith(magic)
    header_length = struct.unpack(">I", current_wire[len(magic):len(magic)+4])[0]
    end = len(magic) + 4 + header_length
    old_reader_header = json.loads(current_wire[len(magic)+4:end])
    assert set(old_reader_header) == {"v", "recipient", "wrapped"}
    assert old_reader_header["v"] == 1 and old_reader_header["recipient"] == recipient
    old_reader_key = identity.decrypt(base64.b64decode(old_reader_header["wrapped"]), oaep)
    old_reader_plain = AESGCM(old_reader_key).decrypt(
        current_wire[end:end+12], current_wire[end+12:], current_wire[:end])
    assert old_reader_plain == plain
