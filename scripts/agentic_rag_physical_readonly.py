"""Strictly read-only Qwen7B / Agent Core RAG E2E on the authorized Dell.

Runs ONLY as a versioned script through an attested Session Launcher worktree
and Command Gateway (risk 1). No Docker, model download, new agent, code edits,
CAS writes, PR creation, worktree deletion, or privileged operations.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping

RUNTIME_REPO = "ericson-j-santos/desktop-pc24x7-runtime"
WORKER_REPO = "ericson-j-santos/engineering-worker-pool"
AGENT_REPO = "ericson-j-santos/agent-core"
RULES_REPO = "ericson-j-santos/chatgpt-operational-rules"
WORKER_SHA = "cb42568c4b70faa0e3e05bb49d5a6e41b884281f"
AGENT_SHA = "1fc032d4c412bdb4ed202cf1193caf0cb49490ce"
RULES_SHA = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"
PR_HEAD = "b083a23af7c55f96ee1c7f8daabbd51167bf4de6"
SOURCE_PATH = "docs/PR_CONTEXT_RETRIEVAL.md"
SOURCE_SHA256 = "b3f7aceab1c5caf0e2aab532189ea4d970aa710120a459f111d7fc9026cfa706"
QUESTION = "Is the GitHub PR context retrieval capability read-only?"
HOST = "DESKTOP-PDQK954"
RUNNER = "DESKTOP-PDQK954-runtime"
PIN = "dae161e27b0e"
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CORRELATION = re.compile(r"[a-z0-9][a-z0-9-]{7,100}\Z")
SESSION = re.compile(r"[A-Za-z0-9._-]{3,100}\Z")


class PhysicalRagBlocked(RuntimeError):
    """Sanitized reason only; never reveal provider output, secrets or local paths."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise PhysicalRagBlocked(code)


def _expected_origin(repository: str) -> str:
    return "https://github.com/" + repository.lower()


def _git(root: Path, *arguments: str) -> str:
    need(root.is_dir() and not root.is_symlink(), "rag_checkout_missing")
    try:
        result = subprocess.run(
            ["git", *arguments], cwd=root, text=True, capture_output=True,
            timeout=15, check=False, env={
                "PATH": os.environ.get("PATH", os.defpath),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
            },
        )
    except (subprocess.TimeoutExpired, OSError):
        raise PhysicalRagBlocked("rag_readonly_git_unavailable") from None
    need(result.returncode == 0 and len(result.stdout) <= 4096,
         "rag_readonly_git_failed")
    return result.stdout.strip()


def check_identity(env: Mapping[str, str]) -> dict[str, str]:
    """Validate the trusted workflow's Session Launcher/Gateway attestation."""
    need(env.get("GITHUB_ACTIONS") == "true" and
         env.get("GITHUB_REPOSITORY") == RUNTIME_REPO,
         "rag_actions_repository_invalid")
    need(env.get("COMPUTERNAME", "").upper() == HOST and
         env.get("RUNNER_NAME") == RUNNER,
         "rag_physical_host_invalid")
    need(env.get("NATIVE_OLLAMA_DEV") == "1" and
         env.get("NATIVE_MODEL_DIGEST_PREFIX") == PIN,
         "rag_native_model_not_approved")
    need(env.get("SESSION_LAUNCH_RESULT") == "SESSION_LAUNCH_OK" and
         env.get("SESSION_STATE_VALIDATED") == "true" and
         env.get("SESSION_GATEWAY_BOUND") == "true",
         "rag_session_or_gateway_unproved")
    session_id = env.get("SESSION_ID", "")
    snapshot = env.get("SESSION_SNAPSHOT_SHA256", "")
    correlation = env.get("CORRELATION_ID", "")
    runtime_sha = env.get("EXPECTED_RUNTIME_SHA", "")
    run_id, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    need(type(session_id) is str and SESSION.fullmatch(session_id) is not None,
         "rag_session_identity_invalid")
    need(type(snapshot) is str and DIGEST.fullmatch(snapshot) is not None,
         "rag_session_snapshot_invalid")
    need(type(correlation) is str and CORRELATION.fullmatch(correlation) is not None,
         "rag_correlation_invalid")
    need(type(runtime_sha) is str and SHA.fullmatch(runtime_sha) is not None,
         "rag_runtime_sha_invalid")
    need(type(run_id) is str and run_id.isdigit() and 1 <= len(run_id) <= 20 and
         type(attempt) is str and attempt.isdigit() and
         1 <= int(attempt) <= 20, "rag_run_identity_invalid")
    target_str = env.get("SESSION_TARGET_PATH", "")
    need(type(target_str) is str and bool(target_str), "rag_worktree_missing")
    target = PureWindowsPath(target_str)
    parts = [part.lower() for part in target.parts]
    need(target.is_absolute() and len(parts) >= 4 and
         parts[:3] == ["c:\\", "dev", "chatgpt-workers"] and
         parts[3].startswith("wt-") and ".." not in parts,
         "rag_worktree_outside_governance")
    return {
        "runtime_sha": runtime_sha, "session_id": session_id,
        "session_snapshot_sha256": snapshot, "correlation_id": correlation,
        "run_id": run_id, "run_attempt": attempt,
    }


def verify_checkouts(env: Mapping[str, str], git=_git) -> dict[str, str]:
    identity = check_identity(env)
    workspace_raw = env.get("GITHUB_WORKSPACE", "")
    need(type(workspace_raw) is str and bool(workspace_raw),
         "rag_actions_workspace_missing")
    workspace = Path(workspace_raw).resolve(strict=True)
    target = Path(env["SESSION_TARGET_PATH"]).resolve(strict=True)
    need(workspace != target and target.is_dir() and
         (target / "scripts" / "agentic_rag_physical_readonly.py").is_file(),
         "rag_session_source_missing")
    roots = (
        (target, RUNTIME_REPO, identity["runtime_sha"]),
        (workspace / "external" / "engineering-worker-pool", WORKER_REPO, WORKER_SHA),
        (workspace / "external" / "agent-core", AGENT_REPO, AGENT_SHA),
        (workspace / "_rules", RULES_REPO, RULES_SHA),
    )
    evidence = {}
    for root, repository, expected in roots:
        need(root.is_dir() and not root.is_symlink(),
             "rag_pinned_checkout_missing")
        observed_sha = git(root, "rev-parse", "HEAD").lower()
        origin = git(root, "remote", "get-url", "origin").lower()
        observed_state = git(root, "status", "--porcelain", "--untracked-files=no")
        need(observed_sha == expected, "rag_pinned_checkout_sha_drift")
        need(origin.rstrip("/").removesuffix(".git") == _expected_origin(repository),
             "rag_checkout_origin_mismatch")
        need(not observed_state, "rag_pinned_checkout_dirty")
        evidence[repository] = observed_sha
    return evidence


def verify_readback(result: Any, reader: Any) -> dict[str, Any]:
    """Independent GitHub PR/bytes readback and exact model-citation attestation."""
    need(type(result) is dict and
         result.get("schema_version") == "worker.rag.evidence-v1" and
         result.get("repository") == AGENT_REPO and
         result.get("pr_number") == 9 and
         result.get("head_sha") == PR_HEAD and
         result.get("state") == "supported" and
         result.get("model_calls") == 2 and
         result.get("model_process_verified") is True and
         result.get("pr_readback_stable") is True and
         result.get("execution_authorized") is False and
         result.get("state_changed") is False,
         "rag_physical_result_invalid")
    model_digest = result.get("model_digest")
    need(type(model_digest) is str and DIGEST.fullmatch(model_digest) is not None and
         model_digest.startswith(PIN), "rag_physical_model_digest_unverified")
    references = result.get("sources")
    citation = result.get("selected_reference")
    need(type(references) is list and len(references) == 1 and
         type(references[0]) is dict and type(citation) is dict,
         "rag_physical_sources_unverified")
    need(references[0].get("path") == SOURCE_PATH and
         references[0].get("ref_sha") == PR_HEAD and
         references[0].get("sha256") == SOURCE_SHA256 and
         citation.get("path") == SOURCE_PATH and
         citation.get("line") == 5 and
         citation.get("source_sha256") == SOURCE_SHA256 and
         citation.get("untrusted_source_text") is True and
         citation.get("url") ==
         f"https://github.com/{AGENT_REPO}/blob/{PR_HEAD}/{SOURCE_PATH}#L5",
         "rag_physical_citation_unverified")
    pr = reader.get_pull_request(AGENT_REPO, 9)
    need(type(pr) is dict and
         pr.get("head", {}).get("sha") == PR_HEAD and
         pr.get("head", {}).get("repo", {}).get("full_name") == AGENT_REPO and
         pr.get("base", {}).get("sha") == result.get("base_sha"),
         "rag_independent_pr_drift")
    file = reader.get_text_file(AGENT_REPO, SOURCE_PATH, PR_HEAD)
    need(type(file) is dict and file.get("path") == SOURCE_PATH and
         file.get("type") == "file" and
         file.get("encoding") == "base64" and
         type(file.get("content")) is str and
         type(file.get("size")) is int and
         type(file.get("sha")) is str and
         SHA.fullmatch(file["sha"]) is not None,
         "rag_independent_source_invalid")
    try:
        raw = base64.b64decode(file["content"].replace("\n", ""), validate=True)
        lines = raw.decode("utf-8").splitlines()
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise PhysicalRagBlocked("rag_independent_source_invalid") from None
    blob_sha = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw
    ).hexdigest()
    need(len(raw) == file["size"] and blob_sha == file["sha"] and
         hashlib.sha256(raw).hexdigest() == SOURCE_SHA256 and
         len(lines) >= 5 and
         lines[4].strip() == citation.get("excerpt") and
         "read-only" in lines[4] and
         "github.pr.context.v1" in lines[4],
         "rag_independent_source_mismatch")
    receipt = result.get("receipt_sha256")
    values = dict(result)
    values.pop("receipt_sha256", None)
    canonical = json.dumps(values, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    need(type(receipt) is str and
         hashlib.sha256(canonical).hexdigest() == receipt,
         "rag_receipt_integrity_invalid")
    return {
        "model_calls": 2, "citation_line": 5,
        "source_sha256": SOURCE_SHA256,
        "model_digest_prefix": model_digest[:12],
        "source_readback_verified": True,
        "pr_readback_verified": True,
        "receipt_sha256_verified": True,
    }


def run_live(env: Mapping[str, str]) -> dict[str, Any]:
    session = check_identity(env)
    before = verify_checkouts(env)
    target = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
    worker_root = target / "external" / "engineering-worker-pool"
    agent_root = target / "external" / "agent-core"
    sys.dont_write_bytecode = True
    # Only locally pre-pinned official code is imported; no dynamic module loading.
    sys.path.insert(0, str(agent_root))
    sys.path.insert(0, str(worker_root))
    from agent_core.pr_context import ContextGitHubHTTPS
    from app.agent_rag_consumer import (
        AgentCoreResearchBridge, NativeQwenResearchPlanner,
        ResearchBlocked, ResearchTask, research_pr,
    )

    token = env.get("GITHUB_TOKEN") or None
    correlation = session["correlation_id"]
    task = ResearchTask(repository=AGENT_REPO, pr_number=9,
                        expected_head=PR_HEAD, correlation_id=correlation,
                        question=QUESTION, source_paths=(SOURCE_PATH,))
    # Real official API negative control MUST precede any physical inference.
    reader = ContextGitHubHTTPS(token)
    planner = NativeQwenResearchPlanner()
    wrong = ResearchTask(repository=AGENT_REPO, pr_number=9,
                         expected_head="f" * 40, correlation_id=correlation,
                         question=QUESTION, source_paths=(SOURCE_PATH,))
    try:
        AgentCoreResearchBridge(reader, planner).research(wrong)
    except ResearchBlocked as exc:
        need(str(exc) == "rag_head_stale_before_model",
             "rag_preflight_negative_wrong_error")
    else:
        raise PhysicalRagBlocked("rag_preflight_negative_missing")
    need(planner.calls == 0, "rag_preflight_negative_spent_inference")
    observed = research_pr(task, github_token=token)
    report = verify_readback(observed, ContextGitHubHTTPS(token))
    need(before == verify_checkouts(env), "rag_local_source_changed")
    return {
        "result": "RAG_PHYSICAL_E2E_VERIFIED",
        "host": HOST, "runner": RUNNER, "repository": RUNTIME_REPO,
        "runtime_sha": session["runtime_sha"],
        "worker_sha": WORKER_SHA, "agent_sha": AGENT_SHA, "rules_sha": RULES_SHA,
        "pr_head_sha": PR_HEAD,
        "run_id": session["run_id"],
        "run_attempt": session["run_attempt"],
        "correlation_id": correlation,
        "session_result": "SESSION_LAUNCH_OK",
        "session_id": session["session_id"],
        "snapshot_sha256": session["session_snapshot_sha256"],
        "state_validated": True,
        "gateway_ok": True,
        "stale_sha_blocked_without_model_calls": True,
        "source_integrity_before_after": True,
        "model_calls": report["model_calls"],
        "model_digest_prefix": report["model_digest_prefix"],
        "citation_line": report["citation_line"],
        "source_sha256": report["source_sha256"],
        "independent_effect_verified": report["source_readback_verified"],
        "pr_readback_verified": report["pr_readback_verified"],
        "receipt_sha256_verified": report["receipt_sha256_verified"],
        "model_writes_authorized": False,
        "merge_or_deploy": False,
    }


def main() -> int:
    try:
        result = run_live(os.environ)
    except Exception as exc:
        allowed = (
            type(exc) is PhysicalRagBlocked and
            re.fullmatch(r"[a-z][a-z0-9_]{2,99}", str(exc)) is not None
        )
        print(json.dumps({
            "result": "RAG_PHYSICAL_E2E_BLOCKED",
            "reason_code": str(exc) if allowed else "rag_physical_dependency_unavailable",
            "merge_or_deploy": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
