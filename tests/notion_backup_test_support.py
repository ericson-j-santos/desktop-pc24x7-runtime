"""Synthetic-only cryptographic material and in-memory draft storage for backup tests."""
from __future__ import annotations

import base64
import copy
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pc24x7_todo_sealed import key_id
from notion_snapshot_fixture import DATABASE_ID, DATA_SOURCE_ID

PRODUCER_SHA = "a" * 40


def key_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    identity = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return identity, public


def hosted_env(public, *, producer_sha=PRODUCER_SHA):
    """This mocked approval is confined to laboratory input; it proves no custody."""
    return {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "ericson-j-santos/desktop-pc24x7-runtime",
        "GITHUB_SHA": producer_sha, "GITHUB_TOKEN": "synthetic-no-network-github-token",
        "TODO_BACKUP_CUSTODY_APPROVAL": "offhost-key-verified",
        "TODO_BACKUP_RECIPIENT_PEM_B64": base64.b64encode(public).decode("ascii"),
        "TODO_BACKUP_RECIPIENT_SHA256": key_id(serialization.load_pem_public_key(public)),
        "TODO_NOTION_READ_TOKEN": "synthetic-no-network-notion-token",
        "TODO_NOTION_DATABASE_ID": DATABASE_ID,
        "TODO_NOTION_DATA_SOURCE_ID": DATA_SOURCE_ID,
        "TODO_NOTION_MIN_PAGES": "2",
    }


class FakeDraftTransport:
    """Only ciphertext is stored; every read returns a separate copy."""
    def __init__(self):
        self.releases = []
        self.assets = {}
        self.payloads = {}
        self.calls = []
        self.uploads = 0
        self.downloads = 0

    def find_draft(self, tag):
        self.calls.append("find_draft")
        matches = [r for r in self.releases if r["tag_name"] == tag]
        assert len(matches) <= 1
        return copy.deepcopy(matches[0]) if matches else None

    def create_or_get_draft(self, tag, sha):
        self.calls.append("create_or_get_draft")
        existing = self.find_draft(tag)
        if existing is not None:
            return existing
        release = {"id": len(self.releases) + 1, "tag_name": tag,
                   "draft": True, "target_commitish": sha}
        self.releases.append(release)
        self.assets[release["id"]] = []
        return copy.deepcopy(release)

    def get_release(self, release_id):
        self.calls.append("get_release")
        return copy.deepcopy(next(r for r in self.releases if r["id"] == release_id))

    def list_assets(self, release_id):
        self.calls.append("list_assets")
        return copy.deepcopy(self.assets[release_id])

    def upload(self, release_id, name, data):
        self.calls.append("upload")
        assert data.startswith(b"TODO-NOTION-SEALED-V1\0"), "synthetic store expects sealed Notion"
        assert next(r for r in self.releases if r["id"] == release_id)["draft"] is True
        self.uploads += 1
        asset_id = 100 + self.uploads
        asset = {"id": asset_id, "name": name, "state": "uploaded",
                 "size": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
        self.payloads[asset_id] = bytes(bytearray(data))
        self.assets[release_id].append(asset)
        return copy.deepcopy(asset)

    def readback(self, asset, limit):
        self.calls.append("readback")
        self.downloads += 1
        return bytes(bytearray(self.payloads[asset["id"]][:limit + 1]))


class NeverClient:
    def request(self, *args, **kwargs):
        raise AssertionError("replay must not access the source")


class CountingClient:
    def __init__(self, inner):
        self.inner = inner
        self.calls = 0

    def request(self, method, path, *, query=None, payload=None):
        self.calls += 1
        return self.inner.request(method, path, query=query, payload=payload)
