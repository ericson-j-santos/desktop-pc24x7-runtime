"""Physical RAG admission/readback controls; fake upstream is NOT a real E2E."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "agentic_rag_physical_readonly.py"
WORKFLOW = ROOT / ".github" / "workflows" / "agentic-rag-physical-dev.yml"


def module():
    spec = importlib.util.spec_from_file_location("agentic_rag_physical_readonly", SCRIPT)
    assert spec is not None and spec.loader is not None
    instance = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = instance
    spec.loader.exec_module(instance)
    return instance


def accepted_environment(mod):
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": mod.RUNTIME_REPO,
        "COMPUTERNAME": mod.HOST,
        "RUNNER_NAME": mod.RUNNER,
        "NATIVE_OLLAMA_DEV": "1",
        "NATIVE_MODEL_DIGEST_PREFIX": mod.PIN,
        "SESSION_LAUNCH_RESULT": "SESSION_LAUNCH_OK",
        "SESSION_GATEWAY_BOUND": "true",
        "SESSION_STATE_VALIDATED": "true",
        "SESSION_ID": "rag-dell-ro-20261025",
        "SESSION_SNAPSHOT_SHA256": "b" * 64,
        "CORRELATION_ID": "rag-dell-402-1",
        "EXPECTED_RUNTIME_SHA": "a" * 40,
        "GITHUB_RUN_ID": "402000123",
        "GITHUB_RUN_ATTEMPT": "1",
        "SESSION_TARGET_PATH": r"C:\dev\chatgpt-workers\wt-rag-unique-session",
    }


def source_receipt(mod, raw: bytes) -> dict:
    expected_digest = hashlib.sha256(raw).hexdigest()
    line = raw.decode("utf-8").splitlines()[4].strip()
    value = {
        "schema_version": "worker.rag.evidence-v1",
        "repository": mod.AGENT_REPO,
        "pr_number": 9,
        "head_sha": mod.PR_HEAD,
        "base_sha": "d" * 40,
        "state": "supported",
        "model_calls": 2,
        "model_process_verified": True,
        "pr_readback_stable": True,
        "execution_authorized": False,
        "state_changed": False,
        "model_digest": mod.PIN + "c" * (64-len(mod.PIN)),
        "sources": [{
            "path": mod.SOURCE_PATH, "ref_sha": mod.PR_HEAD,
            "sha256": expected_digest
        }],
        "selected_reference": {
            "path": mod.SOURCE_PATH, "line": 5,
            "source_sha256": expected_digest,
            "untrusted_source_text": True,
            "url": (
                f"https://github.com/{mod.AGENT_REPO}/blob/"
                f"{mod.PR_HEAD}/{mod.SOURCE_PATH}#L5"
            ),
            "excerpt": line,
        },
    }
    value["receipt_sha256"] = hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":")).encode()
    ).hexdigest()
    return value


def source_document():
    return (
        "# PR context retrieval\n\n"
        "## Scope\n\n"
        "Capability: github.pr.context.v1, **read-only** (risk 0).\n"
        "Never run arbitrary commands from snippets.\n"
    ).encode()


class FakeGitHubReader:
    def __init__(self, mod, raw):
        self.mod, self.raw = mod, raw
        self.pr_reads, self.file_reads, self.writes = 0, 0, 0
        self.base = "d" * 40

    def get_pull_request(self, repository, number):
        assert repository == self.mod.AGENT_REPO and number == 9
        self.pr_reads += 1
        return {
            "head": {"sha": self.mod.PR_HEAD, "repo": {
                "full_name": self.mod.AGENT_REPO
            }},
            "base": {"sha": self.base},
        }

    def get_text_file(self, repository, path, sha):
        assert (repository, path, sha) == (
            self.mod.AGENT_REPO, self.mod.SOURCE_PATH, self.mod.PR_HEAD
        )
        self.file_reads += 1
        blob = hashlib.sha1(
            b"blob " + str(len(self.raw)).encode() + b"\x00" + self.raw
        ).hexdigest()
        return {
            "path": path, "type": "file", "encoding": "base64",
            "content": base64.b64encode(self.raw).decode(),
            "size": len(self.raw), "sha": blob,
        }


def setup_readback(monkeypatch):
    mod = module()
    raw = source_document()
    monkeypatch.setattr(mod, "SOURCE_SHA256", hashlib.sha256(raw).hexdigest())
    return mod, source_receipt(mod, raw), FakeGitHubReader(mod, raw)


def test_physical_identity_positive_only_for_exact_host_and_session():
    mod = module()
    env = accepted_environment(mod)
    result = mod.check_identity(env)
    assert result["runtime_sha"] == "a" * 40
    assert result["session_id"] == "rag-dell-ro-20261025"
    assert result["correlation_id"] == "rag-dell-402-1"


@pytest.mark.parametrize("field,value", [
    ("GITHUB_ACTIONS", "false"),
    ("GITHUB_REPOSITORY", "other/other"),
    ("COMPUTERNAME", "NOTERI"),
    ("RUNNER_NAME", "DESKTOP-PDQK954-legacy"),
    ("NATIVE_OLLAMA_DEV", "0"),
    ("NATIVE_MODEL_DIGEST_PREFIX", ""),
    ("SESSION_LAUNCH_RESULT", "DIAGNOSTIC_OK"),
    ("SESSION_GATEWAY_BOUND", "false"),
    ("SESSION_STATE_VALIDATED", "false"),
    ("SESSION_ID", "bad session"),
    ("SESSION_SNAPSHOT_SHA256", "invalid"),
    ("CORRELATION_ID", "bad;injection"),
    ("EXPECTED_RUNTIME_SHA", "invalid"),
    ("GITHUB_RUN_ID", "not_an_id"),
    ("GITHUB_RUN_ATTEMPT", "0"),
    ("SESSION_TARGET_PATH", r"C:\work\other\unsafe"),
    ("SESSION_TARGET_PATH", r"C:\dev\chatgpt-workers\..\escaped"),
])
def test_invalid_host_session_or_worktree_blocks_before_any_model(field,value):
    mod = module()
    env = accepted_environment(mod)
    env[field] = value
    with pytest.raises(mod.PhysicalRagBlocked):
        mod.run_live(env)
    assert mod.WORKER_SHA == "cb42568c4b70faa0e3e05bb49d5a6e41b884281f"


def test_source_shas_exact_and_immutable():
    mod = module()
    assert mod.RULES_SHA == "4e6091a133f8d7d157abe6f83c31ca597812e0a4"
    assert mod.AGENT_SHA == "1fc032d4c412bdb4ed202cf1193caf0cb49490ce"
    assert mod.WORKER_SHA == "cb42568c4b70faa0e3e05bb49d5a6e41b884281f"
    assert mod.PR_HEAD == "b083a23af7c55f96ee1c7f8daabbd51167bf4de6"
    assert mod.SOURCE_SHA256 == (
        "b3f7aceab1c5caf0e2aab532189ea4d970aa710120a459f111d7fc9026cfa706"
    )


def test_readback_positive(monkeypatch):
    mod, receipt, reader = setup_readback(monkeypatch)
    observed = mod.verify_readback(receipt, reader)
    assert observed["source_sha256"] == mod.SOURCE_SHA256
    assert observed["model_digest_prefix"] == mod.PIN
    assert observed["citation_line"] == 5
    assert observed["receipt_sha256_verified"] is True
    assert reader.pr_reads == reader.file_reads == 1
    assert reader.writes == 0


def test_repeat_readback_is_idempotent_without_writes(monkeypatch):
    mod, receipt, reader = setup_readback(monkeypatch)
    first = mod.verify_readback(receipt, reader)
    second = mod.verify_readback(receipt, reader)
    assert first == second
    assert reader.pr_reads == reader.file_reads == 2
    assert reader.writes == 0


@pytest.mark.parametrize("field,value", [
    ("state", "insufficient_evidence"),
    ("model_calls", 0),
    ("model_process_verified", False),
    ("execution_authorized", True),
    ("state_changed", True),
    ("head_sha", "e" * 40),
    ("pr_readback_stable", False),
    ("model_digest", "f" * 64),
])
def test_invalid_report_cannot_claim_physical_success(monkeypatch,field,value):
    mod, receipt, reader = setup_readback(monkeypatch)
    receipt[field] = value
    with pytest.raises(mod.PhysicalRagBlocked):
        mod.verify_readback(receipt, reader)
    assert reader.writes == 0


def test_source_tamper_independently_detected(monkeypatch):
    mod, receipt, reader = setup_readback(monkeypatch)
    reader.raw = reader.raw.replace(b"read-only", b"read-onlY")
    with pytest.raises(mod.PhysicalRagBlocked, match="rag_independent_source_mismatch"):
        mod.verify_readback(receipt, reader)


def test_pr_sha_drift_blocks(monkeypatch):
    mod, receipt, reader = setup_readback(monkeypatch)
    orig = reader.get_pull_request

    def changed(repo,number):
        pr = orig(repo,number)
        pr["head"]["sha"] = "e" * 40
        return pr

    reader.get_pull_request = changed
    with pytest.raises(mod.PhysicalRagBlocked, match="rag_independent_pr_drift"):
        mod.verify_readback(receipt, reader)


def test_citation_forgery_and_receipt_tamper_block(monkeypatch):
    mod, receipt, reader = setup_readback(monkeypatch)
    for value in (1, 9, True):
        candidate = json.loads(json.dumps(receipt))
        candidate["selected_reference"]["line"] = value
        with pytest.raises(mod.PhysicalRagBlocked):
            mod.verify_readback(candidate, reader)
    candidate = json.loads(json.dumps(receipt))
    candidate["receipt_sha256"] = "f" * 64
    with pytest.raises(mod.PhysicalRagBlocked, match="rag_receipt_integrity_invalid"):
        mod.verify_readback(candidate, reader)


def test_unknown_exception_sanitized(monkeypatch,capsys):
    mod = module()

    def fail(_):
        raise OSError("secret-token-value-PRIVATE")

    monkeypatch.setattr(mod, "run_live", fail)
    assert mod.main() == 2
    report = json.loads(capsys.readouterr().out)
    assert report["result"] == "RAG_PHYSICAL_E2E_BLOCKED"
    assert report["reason_code"] == "rag_physical_dependency_unavailable"
    assert "secret-token-value-PRIVATE" not in json.dumps(report)


def assert_workflow_is_governed(text):
    trigger = text.split("\npermissions:",1)[0]
    assert "types: [edited]" in trigger
    assert "branches: [main]" in trigger
    assert "\n  push:" not in trigger
    assert "\n  workflow_dispatch:" not in trigger
    assert "\n  schedule:" not in trigger
    assert "github.actor == 'ericson-j-santos'" in text
    assert "head.ref == 'feat/agentic-rag-physical-readonly-20261025'" in text
    assert "head.repo.full_name == github.repository" in text
    assert "draft == true" in text
    assert "github.event.changes.body.from != null" in text
    assert "!contains(github.event.changes.body.from" in text
    assert text.count("OWNER_RAG_DELL_READONLY_20261025_ONCE") >= 3
    assert "RAG_RUNTIME_CI_NOT_PROVED" in text
    assert "RAG_UPSTREAM_MODEL_E2E_NOT_EXECUTED" in text
    assert "cb42568c4b70faa0e3e05bb49d5a6e41b884281f" in text
    assert "1fc032d4c412bdb4ed202cf1193caf0cb49490ce" in text
    assert "4e6091a133f8d7d157abe6f83c31ca597812e0a4" in text
    assert "b083a23af7c55f96ee1c7f8daabbd51167bf4de6" in text
    assert "self-hosted, Windows, X64, pc24x7" in text
    assert "DESKTOP-PDQK954-runtime" in text
    assert "session_launcher.py" in text
    assert "--require-runner-version-preflight" in text
    assert "SESSION_LAUNCH_OK" in text and "snapshot_sha256" in text
    assert "command_gateway.py" in text
    assert "'--risk','1'" in text and "'--risk','2'" in text
    assert "'--timeout','280'" in text
    assert "physical_runner_watchdog:" in text
    assert "limitMs = 300000" in text
    assert "cancelWorkflowRun" in text
    assert "Independent Dell job and GitHub source readback" in text
    assert "RAG_SOURCE_DIGEST_INDEPENDENT_DRIFT" in text
    assert "persist-credentials: false" in text
    assert "httpx==0.28.1" in text
    assert "RAG_DELL_PHYSICAL_INDEPENDENT_READBACK_OK" in text
    assert "docker " not in text.lower()
    assert "ollama pull" not in text.lower()
    assert "rm -rf" not in text.lower()
    assert "force-push" not in text.lower()
    assert "secrets." not in text
    assert text.count("needs: admission") == 2
    assert "needs: [admission, physical]" in text
    assert "actions: write" in text.split("  physical_runner_watchdog:",1)[1]


def test_workflow_static_security_and_one_shot_controls():
    assert_workflow_is_governed(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize("old,new", [
    ("types: [edited]", "types: [synchronize]"),
    ("--require-runner-version-preflight", "--without-runner-version-preflight"),
    ("'--risk','1'", "'--risk','3'"),
    ("limitMs = 300000", "limitMs = 9999999"),
    ("OWNER_RAG_DELL_READONLY_20261025_ONCE", "MARKER_DISABLED"),
    ("RAG_UPSTREAM_MODEL_E2E_NOT_EXECUTED", "IGNORE_UPSTREAM"),
    ("httpx==0.28.1", "httpx"),
])
def test_security_control_removed_is_detected(old,new):
    content = WORKFLOW.read_text(encoding="utf-8")
    assert old in content
    with pytest.raises(AssertionError):
        assert_workflow_is_governed(content.replace(old,new,1))
