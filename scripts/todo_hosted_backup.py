"""No-Desktop TODO PG backup: direct Neon -> sealed archive -> authenticated GitHub draft release.

Runs only in guarded GitHub Actions main branch with previously provisioned secrets.
No direct credential output, host operations, schema writes, consumer jobs or cutover.
The draft release is restricted to users with push access and stores only ciphertext.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Protocol

from cryptography.hazmat.primitives import serialization

from pc24x7_todo_recovery import Postgres, RecoveryBlocked, capture, bundle_manifest
from pc24x7_todo_sealed import SealedBlocked, inspect_envelope, key_id, read_file, seal

EXPECTED_REPO = "ericson-j-santos/desktop-pc24x7-runtime"
EXPECTED_HOST = "ep-wandering-glitter-ac1kllv5.sa-east-1.aws.neon.tech"
EXPECTED_DB = "todo_global_bus_dev_ha"
EXPECTED_ROLE = "todo_backup_reader"
MAX_ARCHIVE = 64 * 1024 * 1024 + 128 * 1024 + 16384
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")


class HostedBlocked(RuntimeError):
    """Error code only; never return secrets, local paths or HTTP response bodies."""


def require(ok: Any, code: str) -> None:
    if not ok:
        raise HostedBlocked(code)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_identity(env: dict[str, str]) -> str:
    require(env.get("GITHUB_ACTIONS") == "true", "GITHUB_ACTIONS_REQUIRED")
    require(env.get("GITHUB_EVENT_NAME") in {"push", "schedule", "workflow_dispatch"}, "TRUSTED_EVENT_REQUIRED")
    require(env.get("GITHUB_REF") == "refs/heads/main", "MAIN_ONLY")
    require(env.get("GITHUB_REPOSITORY") == EXPECTED_REPO, "REPOSITORY_MISMATCH")
    commit = env.get("GITHUB_SHA", "")
    require(bool(SHA40.fullmatch(commit)), "HEAD_SHA_REQUIRED")
    require(env.get("TODO_BACKUP_CUSTODY_APPROVAL") == "offhost-key-verified", "CUSTODY_APPROVAL_REQUIRED")
    require(os.name == "posix", "HOSTED_LINUX_REQUIRED")
    return commit


def backup_secret_preflight(env: dict[str, str]) -> bytes:
    password = env.get("TODO_BACKUP_PG_PASSWORD", "")
    require(12 <= len(password) <= 1024 and "\n" not in password and "\r" not in password, "SOURCE_PASSWORD_REFERENCE_MISSING")
    raw = env.get("TODO_BACKUP_RECIPIENT_PEM_B64", "")
    require(0 < len(raw) <= 16384, "PUBLIC_RECIPIENT_REFERENCE_MISSING")
    try:
        pem = base64.b64decode(raw, validate=True)
        key = serialization.load_pem_public_key(pem)
        fingerprint = key_id(key)
    except Exception:
        raise HostedBlocked("RECIPIENT_INVALID") from None
    expected = env.get("TODO_BACKUP_RECIPIENT_SHA256", "")
    require(bool(SHA64.fullmatch(expected)) and expected == fingerprint, "RECIPIENT_ATTESTATION_MISMATCH")
    require(bool(env.get("GITHUB_TOKEN")), "GITHUB_TOKEN_MISSING")
    return pem


def _private_write(path: Path, data: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    require(path.stat().st_mode & 0o077 == 0, "PRIVATE_FILE_PERMISSIONS_UNSAFE")


def build_source_config(root: Path, env: dict[str, str], pem: bytes) -> dict[str, str]:
    """libpq secrets never become shell args, a DSN, a log or a GitHub artifact."""
    password = env["TODO_BACKUP_PG_PASSWORD"]
    escaped = password.replace("\\", "\\\\").replace(":", "\\:")
    _private_write(root / "pgpass", f"{EXPECTED_HOST}:5432:{EXPECTED_DB}:{EXPECTED_ROLE}:{escaped}\n".encode())
    _private_write(root / "pg_service.conf", (
        f"[todo_recovery_source]\nhost={EXPECTED_HOST}\nport=5432\ndbname={EXPECTED_DB}\n"
        f"user={EXPECTED_ROLE}\nsslmode=verify-full\nsslrootcert=/etc/ssl/certs/ca-certificates.crt\n"
    ).encode())
    _private_write(root / "recipient.pem", pem)
    return {"PGSERVICEFILE": str(root / "pg_service.conf"), "PGPASSFILE": str(root / "pgpass")}


class Transport(Protocol):
    def find_draft(self, tag: str) -> dict | None: ...
    def create_or_get_draft(self, tag: str, sha: str) -> dict: ...
    def get_release(self, release_id: int) -> dict: ...
    def list_assets(self, release_id: int) -> list[dict]: ...
    def upload(self, release_id: int, name: str, data: bytes) -> dict: ...
    def readback(self, asset: dict, limit: int) -> bytes: ...


class NoBearerRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward privileged GitHub bearer tokens to a redirect target."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubDraftTransport:
    """Fixed GitHub owner/repo and exact API destinations; no dynamic URL routing."""

    def __init__(self, token: str):
        require(bool(token), "GITHUB_TOKEN_MISSING")
        self.token = token

    def _request(self, method: str, url: str, data: bytes | None = None,
                 content_type: str = "application/vnd.github+json", limit: int = 1024 * 1024) -> tuple[int, bytes]:
        parsed = urllib.parse.urlparse(url)
        require(parsed.scheme == "https" and parsed.hostname in {"api.github.com", "uploads.github.com"} and
                parsed.username is None and parsed.password is None and parsed.port is None,
                "UNTRUSTED_GITHUB_API_HOST")
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "Content-Type": content_type,
            "User-Agent": "todo-recovery-hosted-safe/1",
        })
        try:
            with urllib.request.build_opener(NoBearerRedirect).open(request, timeout=25) as response:
                require(response.geturl().startswith("https://" + parsed.hostname + "/"),
                        "AUTHENTICATED_API_REDIRECT_BLOCKED")
                return response.status, response.read(limit + 1)
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return 404, b""
            if 300 <= err.code < 400:
                raise HostedBlocked("AUTHENTICATED_API_REDIRECT_BLOCKED") from None
            raise HostedBlocked("GITHUB_API_WRITE_OR_READ_BLOCKED") from None
        except (OSError, TimeoutError):
            raise HostedBlocked("GITHUB_API_UNAVAILABLE") from None

    def _json(self, method: str, url: str, payload: dict | None = None) -> tuple[int, Any]:
        code, data = self._request(method, url, None if payload is None else json.dumps(payload).encode())
        if code == 404:
            return 404, None
        require(0 < len(data) < 1024 * 1024, "GITHUB_RESPONSE_SIZE_INVALID")
        try:
            return code, json.loads(data)
        except (ValueError, UnicodeError):
            raise HostedBlocked("GITHUB_RESPONSE_INVALID") from None

    def find_draft(self, tag: str) -> dict | None:
        matches = []
        for page in range(1, 11):
            url = ("https://api.github.com/repos/" + EXPECTED_REPO +
                   f"/releases?per_page=100&page={page}")
            code, releases = self._json("GET", url)
            require(code == 200 and isinstance(releases, list), "RELEASE_LIST_INVALID")
            matches.extend(r for r in releases if isinstance(r, dict) and r.get("tag_name") == tag)
            require(len(matches) <= 1, "DUPLICATE_RELEASE_TAG")
            if len(releases) < 100:
                break
        else:
            raise HostedBlocked("RELEASE_LIST_LIMIT_REACHED")
        if not matches:
            return None
        release = matches[0]
        require(release.get("draft") is True and type(release.get("id")) is int
                and release["id"] > 0, "DRAFT_RELEASE_REQUIRED")
        return release

    def create_or_get_draft(self, tag: str, sha: str) -> dict:
        require(isinstance(sha, str) and bool(SHA40.fullmatch(sha)), "HEAD_SHA_REQUIRED")
        release = self.find_draft(tag)
        if release is None:
            code, release = self._json("POST", "https://api.github.com/repos/" + EXPECTED_REPO + "/releases", {
                "tag_name": tag, "name": "Encrypted TODO backup " + tag,
                "target_commitish": sha, "draft": True, "prerelease": True,
                "make_latest": "false", "body": "Encrypted TODO snapshot. No plaintext or recovery key. Not an operational cutover.",
            })
            require(code == 201, "DRAFT_RELEASE_CREATION_FAILED")
        require(isinstance(release, dict) and release.get("draft") is True and
                type(release.get("id")) is int and release["id"] > 0 and release.get("tag_name") == tag,
                "DRAFT_RELEASE_REQUIRED")
        return release

    def get_release(self, release_id: int) -> dict:
        require(type(release_id) is int and release_id > 0, "RELEASE_ID_INVALID")
        code, data = self._json("GET", f"https://api.github.com/repos/{EXPECTED_REPO}/releases/{release_id}")
        require(code == 200 and isinstance(data, dict), "RELEASE_READBACK_FAILED")
        return data

    def list_assets(self, release_id: int) -> list[dict]:
        code, data = self._json("GET", f"https://api.github.com/repos/{EXPECTED_REPO}/releases/{release_id}/assets?per_page=100")
        require(code == 200 and isinstance(data, list) and len(data) < 100, "RELEASE_ASSETS_INVALID")
        return data

    def upload(self, release_id: int, name: str, data: bytes) -> dict:
        require(name.endswith(".sealed") and 0 < len(data) <= MAX_ARCHIVE, "SEALED_ARCHIVE_REQUIRED")
        query = urllib.parse.urlencode({"name": name})
        code, response = self._request("POST", f"https://uploads.github.com/repos/{EXPECTED_REPO}/releases/{release_id}/assets?{query}",
                                      data, "application/octet-stream")
        require(code == 201 and response, "SEALED_RELEASE_UPLOAD_FAILED")
        try:
            asset = json.loads(response)
        except (ValueError, UnicodeError):
            raise HostedBlocked("ASSET_RESPONSE_INVALID") from None
        require(asset.get("name") == name and asset.get("state") == "uploaded", "ASSET_UPLOAD_UNVERIFIED")
        return asset

    def readback(self, asset: dict, limit: int) -> bytes:
        """Download authenticated draft asset through API; reject redirects of bearer token."""
        require(type(asset.get("id")) is int and asset["id"] > 0, "ASSET_ID_INVALID")
        api = f"https://api.github.com/repos/{EXPECTED_REPO}/releases/assets/{asset['id']}"
        request = urllib.request.Request(api, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/octet-stream",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "todo-recovery-hosted-safe/1",
        })
        # The authenticated request NEVER follows bearer-bearing redirects.
        opener = urllib.request.build_opener(NoBearerRedirect)
        try:
            try:
                resp = opener.open(request, timeout=30)
            except urllib.error.HTTPError as e:
                if e.code not in (301, 302, 303, 307, 308):
                    raise HostedBlocked("DRAFT_ASSET_READBACK_FAILED") from None
                target = e.headers.get("Location", "")
                parsed = urllib.parse.urlparse(target)
                require(parsed.scheme == "https" and parsed.hostname in {
                    "objects.githubusercontent.com", "release-assets.githubusercontent.com"
                }, "ASSET_REDIRECT_UNTRUSTED")
                # No Authorization on the signed URL. It already grants a bounded encrypted download.
                req = urllib.request.Request(target, headers={"User-Agent": "todo-recovery-hosted-safe/1"})
                resp = urllib.request.urlopen(req, timeout=30)
            with resp:
                return resp.read(limit + 1)
        except HostedBlocked:
            raise
        except (OSError, urllib.error.HTTPError, TimeoutError):
            raise HostedBlocked("DRAFT_ASSET_READBACK_FAILED") from None


def release_producer(release: dict, tag: str) -> str:
    """Observe a pinned release revision; only decrypted manifest proves its binding."""
    require(isinstance(release, dict) and release.get("draft") is True and
            type(release.get("id")) is int and release["id"] > 0 and
            release.get("tag_name") == tag, "DRAFT_RELEASE_REQUIRED")
    producer = release.get("target_commitish", "")
    require(isinstance(producer, str) and bool(SHA40.fullmatch(producer)),
            "BACKUP_PRODUCER_SHA_REQUIRED")
    return producer


def final_storage_readback(transport: Transport, release_id: int, tag: str,
                           producer: str, asset: dict, digest: str, size: int) -> None:
    """Independent metadata read after download; not authenticated capture provenance."""
    matches = [a for a in transport.list_assets(release_id)
               if isinstance(a, dict) and a.get("name") == asset["name"]]
    require(len(matches) == 1, "FINAL_ASSET_SET_CHANGED")
    observed = matches[0]
    require(type(asset.get("id")) is int and asset["id"] > 0 and
            observed.get("id") == asset["id"] and observed.get("state") == "uploaded" and
            observed.get("digest") == "sha256:" + digest and
            type(observed.get("size")) is int and observed["size"] == size,
            "FINAL_ASSET_IDENTITY_CHANGED")
    current = transport.get_release(release_id)
    observed_producer = release_producer(current, tag)
    require(current["id"] == release_id and observed_producer == producer,
            "RELEASE_IDENTITY_CHANGED")


def already_uploaded(transport: Transport, name: str, tag: str, *, recipient_pem: bytes,
                     inspector: Callable[[bytes, bytes], dict] | None = None) -> dict | None:
    """Idempotent repeat: validate a previous encrypted offsite file before reconnecting to Neon."""
    release = transport.find_draft(tag)
    if release is None:
        return None
    producer = release_producer(release, tag)
    assets = transport.list_assets(release["id"])
    matches = [a for a in assets if isinstance(a, dict) and a.get("name") == name]
    require(len(matches) <= 1, "DUPLICATE_ASSET_NAME")
    if not matches:
        return None
    asset = matches[0]
    digest = asset.get("digest", "")
    require(isinstance(digest, str) and digest.startswith("sha256:") and
            bool(SHA64.fullmatch(digest[7:])) and asset.get("state") == "uploaded",
            "TRUSTED_OFFSITE_DIGEST_MISSING")
    remote = transport.readback(asset, MAX_ARCHIVE)
    require(isinstance(remote, bytes) and 0 < len(remote) <= MAX_ARCHIVE and
            (inspector is not None or remote.startswith(b"TODO-PG-SEALED-V1\0")) and
            sha256(remote) == digest[7:], "OFFSITE_CIPHERTEXT_READBACK_MISMATCH")
    inspected = (inspect_envelope if inspector is None else inspector)(remote, recipient_pem)
    final_storage_readback(transport, release["id"], tag, producer, asset, digest[7:], len(remote))
    return {"state": "already_verified", "release_producer_sha": producer, "ciphertext_sha256": digest[7:],
            "recipient": inspected["header"]["recipient"], "recipient_matched": True,
            "envelope_structure_verified": True, "ciphertext_authentication_verified": False,
            "ciphertext_bytes": len(remote), "release_id": release["id"],
            "asset_id": asset["id"], "storage_private_draft": True,
            "database_restore_verified": False, "offhost_custody_verified": False,
            "cutover_ready": False, "workers_started": False, "replay_without_source_access": True}


def verified_upload(transport: Transport, name: str, cipher: bytes, tag: str, sha: str,
                    *, recipient_pem: bytes,
                    inspector: Callable[[bytes, bytes], dict] | None = None) -> dict:
    require(isinstance(sha, str) and bool(SHA40.fullmatch(sha)), "HEAD_SHA_REQUIRED")
    require(isinstance(cipher, bytes) and 0 < len(cipher) <= MAX_ARCHIVE and
            (inspector is not None or cipher.startswith(b"TODO-PG-SEALED-V1\0")),
            "CIPHERTEXT_FORMAT_INVALID")
    inspected = (inspect_envelope if inspector is None else inspector)(cipher, recipient_pem)
    digest = sha256(cipher)
    release = transport.create_or_get_draft(tag, sha)
    producer = release_producer(release, tag)
    require(producer == sha, "RELEASE_PRODUCER_SHA_MISMATCH")
    assets = transport.list_assets(release["id"])
    matches = [a for a in assets if isinstance(a, dict) and a.get("name") == name]
    require(len(matches) <= 1, "DUPLICATE_ASSET_NAME")
    if matches:
        asset = matches[0]
        replay = True
    else:
        asset = transport.upload(release["id"], name, cipher)
        replay = False
    require(asset.get("name") == name and asset.get("state") == "uploaded", "ASSET_STATE_UNVERIFIED")
    observed = transport.readback(asset, MAX_ARCHIVE)
    require(len(observed) == len(cipher) and sha256(observed) == digest,
            "OFFSITE_CIPHERTEXT_READBACK_MISMATCH")
    final_storage_readback(transport, release["id"], tag, producer, asset, digest, len(cipher))
    return {"state": "already_verified" if replay else "encrypted_draft_uploaded",
            "release_producer_sha": producer,
            "ciphertext_sha256": digest, "ciphertext_bytes": len(cipher),
            "recipient": inspected["header"]["recipient"], "recipient_matched": True,
            "envelope_structure_verified": True, "ciphertext_authentication_verified": False,
            "release_id": release["id"], "asset_id": asset["id"],
            "storage_private_draft": True, "database_restore_verified": False,
            "offhost_custody_verified": False, "cutover_ready": False, "workers_started": False}


def run(env: dict[str, str], transport: Transport, *, bin_dir: Path) -> dict:
    commit = git_identity(env)
    pem = backup_secret_preflight(env)
    tag = "todo-pg-backup-" + datetime.now(timezone.utc).strftime("%Y%m%d")
    name = tag + ".sealed"
    previously = already_uploaded(transport, name, tag, recipient_pem=pem)
    if previously is not None:
        # The current execution did not capture this asset or inspect its encrypted manifest.
        # Never relabel a prior backup with this execution\'s source identity.
        return {**previously, "executor_sha": commit, "source_sha": None, "source_db": None,
                "capture_executed": False, "production_data_read": False}
    # Fail closed on a pre-existing untrusted output path; use only ephemeral runner temp.
    with tempfile.TemporaryDirectory(prefix="todo-hosted-backup-") as location:
        root = Path(location)
        root.chmod(0o700)
        source_env = build_source_config(root, env, pem)
        pg = Postgres(bin_dir, source_env)
        bundle = root / "bundle"
        result = capture(pg, bundle, "todo-hosted-backup-" + tag)
        require(result["state"] in {"captured", "already_captured"}, "SOURCE_CAPTURE_FAILED")
        manifest = bundle_manifest(bundle)
        # Bind the producer revision inside the encrypted payload as well as release metadata.
        manifest["producer_sha"] = commit
        bound_manifest = bundle / "manifest.bound.json"
        _private_write(bound_manifest, json.dumps(manifest, sort_keys=True).encode("utf-8") + b"\n")
        bound_manifest.replace(bundle / "manifest.json")
        manifest = bundle_manifest(bundle)
        # Refuse an apparently empty or partial production export.
        require("queue_events" in manifest["tables"] and "continuation_requests" in manifest["tables"],
                "REQUIRED_TABLES_MISSING")
        archive = bundle / "database.dump"
        require(archive.stat().st_size <= 64 * 1024 * 1024, "BACKUP_TOO_LARGE")
        encrypted = root / name
        receipt = seal(bundle, encrypted, root / "recipient.pem")
        require(receipt["state"] == "sealed", "BACKUP_ENCRYPTION_FAILED")
        cipher = read_file(encrypted, MAX_ARCHIVE)
        require(sha256(cipher) == receipt["ciphertext_sha256"], "CIPHERTEXT_DIGEST_MISMATCH")
        uploaded = verified_upload(transport, name, cipher, tag, commit, recipient_pem=pem)
        return {**uploaded, "executor_sha": commit, "source_sha": commit, "source_db": EXPECTED_DB,
                "capture_executed": True,
                "source_major": manifest["source_major"], "table_count": len(manifest["tables"]),
                "source_rows": sum(int(x["rows"]) for x in manifest["tables"].values()),
                "production_data_read": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        env = dict(os.environ)
        value = run(env, GitHubDraftTransport(env.get("GITHUB_TOKEN", "")), bin_dir=args.bin_dir)
        # Only sanitized receipt; never print source rows, password, data, private key, archive or URLs.
    except (HostedBlocked, RecoveryBlocked, SealedBlocked) as err:
        value = {"state": "blocked", "reason": str(err), "cutover_ready": False}
    except Exception:
        value = {"state": "blocked", "reason": "HOSTED_BACKUP_UNEXPECTED_FAILURE", "cutover_ready": False}
    print(json.dumps(value, sort_keys=True))
    return 2 if value["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
