"""Safety tests for hosted backup. Synthetic key/data only; no network or real DB."""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
spec = importlib.util.spec_from_file_location("hosted_backup_unit", SCRIPT_DIR / "todo_hosted_backup.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


@pytest.fixture(scope="module")
def pubkey():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture
def env(pubkey):
    public = serialization.load_pem_public_key(pubkey)
    return {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "schedule",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "ericson-j-santos/desktop-pc24x7-runtime",
        "GITHUB_SHA": "a" * 40,
        "TODO_BACKUP_PG_PASSWORD": "safe-synthetic-password-1234",
        "TODO_BACKUP_RECIPIENT_PEM_B64": base64.b64encode(pubkey).decode("ascii"),
        "TODO_BACKUP_RECIPIENT_SHA256": b.key_id(public),
        "TODO_BACKUP_CUSTODY_APPROVAL": "offhost-key-verified",
        "GITHUB_TOKEN": "synthetic-token-not-valid",
    }


class FakeRelease:
    def __init__(self):
        self.releases = {}
        self.assets = {}
        self.calls = []
        self.corrupt = False
        self.published = False
        self.id_counter = 100

    def find_draft(self, tag):
        self.calls.append("find_draft")
        return self.releases.get(tag)

    def create_or_get_draft(self, tag, sha):
        self.calls.append("get_draft")
        if tag not in self.releases:
            self.releases[tag] = {"tag_name": tag, "id": 42, "draft": not self.published}
        return self.releases[tag]

    def list_assets(self, release_id):
        self.calls.append("list_assets")
        return [dict(asset) for asset, _ in self.assets.values()]

    def upload(self, release_id, name, data):
        self.calls.append("upload")
        self.id_counter += 1
        asset = {"id": self.id_counter, "name": name, "state": "uploaded", "digest": "sha256:" + b.sha256(data)}
        self.assets[name] = (asset, bytes(data))
        return asset

    def readback(self, asset, limit):
        self.calls.append("readback")
        data = self.assets[asset["name"]][1]
        return data + b"bad" if self.corrupt else data


def synthetic_cipher():
    # Verify transport never sends plaintext; the cryptography module is validated
    # independently by the real PostgreSQL E2E and portable-sealed tests.
    return b"TODO-PG-SEALED-V1\0" + os.urandom(300)


def test_positive_upload_and_replay_does_not_create_second_asset(env):
    dest = FakeRelease()
    key = synthetic_cipher()
    one = b.verified_upload(dest, "todo-pg-backup-20261018.sealed", key, "todo-pg-backup-20261018", env["GITHUB_SHA"])
    again = b.verified_upload(dest, "todo-pg-backup-20261018.sealed", key, "todo-pg-backup-20261018", env["GITHUB_SHA"])
    assert one["state"] == "encrypted_draft_uploaded"
    assert again["state"] == "already_verified"
    assert dest.calls.count("upload") == 1
    assert one["ciphertext_sha256"] == b.sha256(key)
    assert one["storage_private_draft"] and not one["database_restore_verified"]
    assert not one["cutover_ready"] and not one["offhost_custody_verified"]
    assert not one["workers_started"]


def test_readback_mutation_fails_and_never_declares_success(env):
    dest = FakeRelease()
    dest.corrupt = True
    with pytest.raises(b.HostedBlocked, match="OFFSITE_CIPHERTEXT_READBACK_MISMATCH"):
        b.verified_upload(dest, "todo-pg-backup-20261018.sealed", synthetic_cipher(), "todo-pg-backup-20261018", env["GITHUB_SHA"])
    assert dest.calls.count("upload") == 1


def test_preexisting_different_asset_is_not_overwritten(env):
    dest = FakeRelease()
    name = "todo-pg-backup-20261018.sealed"
    data = synthetic_cipher()
    b.verified_upload(dest, name, data, "todo-pg-backup-20261018", env["GITHUB_SHA"])
    with pytest.raises(b.HostedBlocked, match="OFFSITE_CIPHERTEXT_READBACK_MISMATCH"):
        b.verified_upload(dest, name, synthetic_cipher(), "todo-pg-backup-20261018", env["GITHUB_SHA"])
    assert dest.assets[name][1] == data and dest.calls.count("upload") == 1


@pytest.mark.parametrize("field,value,reason", [
    ("GITHUB_ACTIONS", "false", "GITHUB_ACTIONS_REQUIRED"),
    ("GITHUB_EVENT_NAME", "pull_request", "TRUSTED_EVENT_REQUIRED"),
    ("GITHUB_EVENT_NAME", "push", "TRUSTED_EVENT_REQUIRED"),
    ("GITHUB_REF", "refs/heads/feat/example", "MAIN_ONLY"),
    ("GITHUB_REPOSITORY", "untrusted/same-named", "REPOSITORY_MISMATCH"),
    ("GITHUB_SHA", "bad", "HEAD_SHA_REQUIRED"),
    ("TODO_BACKUP_CUSTODY_APPROVAL", "", "CUSTODY_APPROVAL_REQUIRED"),
    ("TODO_BACKUP_CUSTODY_APPROVAL", "approved-by-ci-mock", "CUSTODY_APPROVAL_REQUIRED"),
])
def test_hosted_execution_refuses_untrusted_context(env,field,value,reason):
    env[field] = value
    with pytest.raises(b.HostedBlocked, match=reason):
        b.git_identity(env)


@pytest.mark.parametrize("field,value,reason", [
    ("TODO_BACKUP_PG_PASSWORD", "", "SOURCE_PASSWORD_REFERENCE_MISSING"),
    ("TODO_BACKUP_PG_PASSWORD", "abc\nprivate", "SOURCE_PASSWORD_REFERENCE_MISSING"),
    ("TODO_BACKUP_RECIPIENT_PEM_B64", "", "PUBLIC_RECIPIENT_REFERENCE_MISSING"),
    ("TODO_BACKUP_RECIPIENT_PEM_B64", "eHm=", "RECIPIENT_INVALID"),
    ("TODO_BACKUP_RECIPIENT_SHA256", "b"*64, "RECIPIENT_ATTESTATION_MISMATCH"),
    ("GITHUB_TOKEN", "", "GITHUB_TOKEN_MISSING"),
])
def test_must_have_strong_pregoverned_secret_refs(env,field,value,reason):
    env[field] = value
    with pytest.raises(b.HostedBlocked, match=reason):
        b.backup_secret_preflight(env)


def test_source_service_is_exact_unpooled_and_credential_only_in_pgpass(tmp_path,env,pubkey):
    root=tmp_path/"private";root.mkdir(mode=0o700)
    returned=b.build_source_config(root,env,pubkey)
    profile=(root/"pg_service.conf").read_text()
    pgpass=(root/"pgpass").read_text()
    assert b.EXPECTED_HOST in profile and "-pooler" not in profile
    assert "sslmode=verify-full" in profile
    assert "sslrootcert=/etc/ssl/certs/ca-certificates.crt" in profile
    assert "user=todo_backup_reader" in profile
    assert "dbname=todo_global_bus_dev_ha" in profile
    assert env["TODO_BACKUP_PG_PASSWORD"] not in profile
    assert env["TODO_BACKUP_PG_PASSWORD"] in pgpass
    assert returned == {"PGSERVICEFILE":str(root/"pg_service.conf"),"PGPASSFILE":str(root/"pgpass")}
    assert all((root/name).stat().st_mode & 0o077 == 0 for name in ("pg_service.conf","pgpass","recipient.pem"))


def test_pgpass_safely_escapes_colon_and_backslash(tmp_path,env,pubkey):
    root=tmp_path/"private";root.mkdir(mode=0o700)
    env["TODO_BACKUP_PG_PASSWORD"]="safe:synth\\word-strong"
    b.build_source_config(root,env,pubkey)
    assert (root/"pgpass").read_text().endswith(":safe\\:synth\\\\word-strong\n")


def test_git_authenticated_api_redirects_never_forward_bearer():
    assert b.NoBearerRedirect().redirect_request(None,None,302,"Found",{},"https://attacker.invalid/") is None
    api=b.GitHubDraftTransport("synthetic")
    with pytest.raises(b.HostedBlocked,match="UNTRUSTED_GITHUB_API_HOST"):
        api._request("GET","https://attacker.invalid/bad")
    with pytest.raises(b.HostedBlocked,match="UNTRUSTED_GITHUB_API_HOST"):
        api._request("GET","https://api.github.com.attacker.invalid/bad")


def test_replay_rejects_duplicate_assets(env):
    class Duplicate(FakeRelease):
        def list_assets(self,release_id):
            name="todo-pg-backup-20261018.sealed"
            return [{"id":1,"name":name,"state":"uploaded"},{"id":2,"name":name,"state":"uploaded"}]
    with pytest.raises(b.HostedBlocked, match="DUPLICATE_ASSET_NAME"):
        b.verified_upload(Duplicate(),"todo-pg-backup-20261018.sealed",synthetic_cipher(),"todo-pg-backup-20261018",env["GITHUB_SHA"])


def test_rejects_unsealed_blob_before_network(env):
    fake=FakeRelease()
    with pytest.raises(b.HostedBlocked,match="CIPHERTEXT_FORMAT_INVALID"):
        b.verified_upload(fake,"todo-pg-backup-20261018.sealed",b"PGDMP-not-sealed","todo-pg-backup-20261018",env["GITHUB_SHA"])
    assert fake.calls == []


def test_workflow_main_only_never_exposes_secrets_in_pr():
    workflow=(ROOT/".github/workflows/todo-hosted-backup.yml").read_text()
    assert "runs-on: ubuntu-latest" in workflow and "self-hosted" not in workflow
    assert "environment: todo-pg-backup" in workflow
    assert "github.event_name == 'schedule'" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "if: github.event_name == 'pull_request' || github.event_name == 'push'" in workflow
    assert "contents: read" in workflow and "contents: write" in workflow
    assert workflow.index("contents: read") < workflow.index("contents: write")
    assert "persist-credentials: false" in workflow
    assert "uses: actions/upload-artifact" not in workflow
    assert not any(line.lstrip().startswith("cache:") for line in workflow.splitlines() if not line.lstrip().startswith("#"))
    assert "python3 scripts/todo_hosted_backup.py --bin-dir /usr/lib/postgresql/18/bin" in workflow
    assert "secrets.TODO_BACKUP_PG_PASSWORD" in workflow
    assert "secrets.TODO_BACKUP_RECIPIENT_PEM_B64" in workflow


def test_runbook_distinguishes_export_from_restore_and_requires_custody():
    doc=(ROOT/"docs/todo-hosted-backup.md").read_text()
    for term in ("offhost-key-verified", "todo_backup_reader", "draft release", "PGPASSFILE",
                 "pg_dump", "cutover_ready=false", "SEM", "restore", "Neon"):
        assert term.lower() in doc.lower()


def test_no_external_job_can_use_untrusted_artifact_or_runtime():
    script=(SCRIPT_DIR/"todo_hosted_backup.py").read_text()
    assert 'EXPECTED_REPO = "ericson-j-santos/desktop-pc24x7-runtime"' in script
    assert 'EXPECTED_ROLE = "todo_backup_reader"' in script
    assert "SHELL" not in script and "shell=True" not in script
    for dangerous in ("CREATE ROLE", "ALTER ROLE", "DROP DATABASE", "start-workers", "disable-auth"):
        assert dangerous not in script


def test_published_release_is_refused_before_upload(env):
    fake=FakeRelease()
    fake.published=True
    with pytest.raises(b.HostedBlocked,match="DRAFT_RELEASE_REQUIRED"):
        b.verified_upload(fake,"todo-pg-backup-20261018.sealed",synthetic_cipher(),"todo-pg-backup-20261018",env["GITHUB_SHA"])
    assert fake.calls == ["get_draft"]


def test_same_day_retry_readback_without_neon_source_reconnect(env):
    fake=FakeRelease()
    tag="todo-pg-backup-20261018"
    asset=tag+".sealed"
    data=synthetic_cipher()
    assert b.already_uploaded(fake,asset,tag) is None
    b.verified_upload(fake,asset,data,tag,env["GITHUB_SHA"])
    previous_uploads=fake.calls.count("upload")
    receipt=b.already_uploaded(fake,asset,tag)
    assert receipt["state"]=="already_verified" and receipt["replay_without_source_access"]
    assert fake.calls.count("upload")==previous_uploads and receipt["ciphertext_sha256"]==b.sha256(data)

def test_remote_asset_digest_missing_blocks_replay(env):
    fake=FakeRelease()
    tag="todo-pg-backup-20261018"
    asset=tag+".sealed"
    b.verified_upload(fake,asset,synthetic_cipher(),tag,env["GITHUB_SHA"])
    fake.assets[asset][0].pop("digest")
    with pytest.raises(b.HostedBlocked,match="TRUSTED_OFFSITE_DIGEST_MISSING"):
        b.already_uploaded(fake,asset,tag)

def test_corrupted_existing_asset_blocks_replay_without_new_upload(env):
    fake=FakeRelease()
    tag="todo-pg-backup-20261018"
    asset=tag+".sealed"
    b.verified_upload(fake,asset,synthetic_cipher(),tag,env["GITHUB_SHA"])
    fake.corrupt=True
    with pytest.raises(b.HostedBlocked,match="OFFSITE_CIPHERTEXT_READBACK_MISMATCH"):
        b.already_uploaded(fake,asset,tag)
    assert fake.calls.count("upload")==1
