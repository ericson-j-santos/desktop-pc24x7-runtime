"""Read-only physical admission and real issue-scoped Qwen RAG on Dell.

Everything here is deliberately pre-PR: no lease, commands chosen by a model,
CAS writes, code modification, Git push or deployment. The trusted Builder/
Validator/CAS code lives exclusively in the SHA-pinned Worker Pool checkout.

Run ONLY via the canonical Session Launcher + Command Gateway on an authorized
Dell runner after hosted owner/HEAD and CI admission.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HOST_REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
WORKER_REPOSITORY = "ericson-j-santos/engineering-worker-pool"
WORKER_SHA = "047c77b6b867ff5d489bd74f6fd80989719ab85e"
RULES_SHA = "92e8b5c87684212964b24ff3597f9f9f8aea49a6"
SOURCE_PATH = "app/portfolio_bridge.py"
SOURCE_BLOB_SHA = "d9a25c574163c49f695e774609949160d94f4490"
ISSUE_NUMBER = 8
OWNER_COMMENT_ID = 6423646539
MODEL_PIN = "dae161e27b0e"
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
CORRELATION = re.compile(r"[a-z0-9][a-z0-9-]{7,120}\Z")


_PHASE = "identity"
_PHASES = frozenset((
    "identity", "checkouts", "agent_core", "imports", "owner",
    "baseline", "model", "research", "readback",
))

def _set_phase(phase: str) -> None:
    global _PHASE
    if phase not in _PHASES:
        raise PreflightBlocked("issue8_phase_invalid")
    _PHASE = phase


class PreflightBlocked(RuntimeError):
    """Never contain user input, remote API body, paths, or credentials."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise PreflightBlocked(code)


def validate_environment(env: dict[str, str]) -> dict[str, str]:
    require(env.get("GITHUB_ACTIONS") == "true"
            and env.get("GITHUB_REPOSITORY") == HOST_REPOSITORY,
            "issue8_actions_repository_invalid")
    require(env.get("COMPUTERNAME", "").upper() == "DESKTOP-PDQK954",
            "issue8_wrong_physical_computer")
    require(env.get("RUNNER_NAME") == "DESKTOP-PDQK954-runtime",
            "issue8_wrong_runner")
    require(env.get("NATIVE_OLLAMA_DEV") == "1"
            and env.get("NATIVE_MODEL_DIGEST_PREFIX") == MODEL_PIN,
            "issue8_model_not_approved")
    require(env.get("SESSION_LAUNCH_RESULT") == "SESSION_LAUNCH_OK"
            and env.get("SESSION_STATE_VALIDATED") == "true"
            and env.get("SESSION_GATEWAY_BOUND") == "true",
            "issue8_session_or_gateway_unverified")
    session = env.get("SESSION_ID", "")
    snapshot = env.get("SESSION_SNAPSHOT_SHA256", "")
    correlation = env.get("CORRELATION_ID", "")
    runtime_sha = env.get("EXPECTED_RUNTIME_SHA", "")
    run, attempt = env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", "")
    require(bool(re.fullmatch(r"[A-Za-z0-9._-]{3,64}", session)),
            "issue8_session_invalid")
    require(bool(SHA64.fullmatch(snapshot)),
            "issue8_session_snapshot_invalid")
    require(bool(CORRELATION.fullmatch(correlation)),
            "issue8_correlation_invalid")
    require(bool(SHA40.fullmatch(runtime_sha)),
            "issue8_host_sha_invalid")
    require(run.isdigit() and len(run) <= 20
            and attempt.isdigit() and 1 <= int(attempt) <= 20,
            "issue8_run_identity_invalid")
    require(env.get("WORKER_POOL_SHA") == WORKER_SHA
            and env.get("RULES_SHA") == RULES_SHA,
            "issue8_pinned_source_mismatch")
    workspace = env.get("GITHUB_WORKSPACE", "")
    require(bool(workspace), "issue8_checkout_path_missing")
    return {
        "runtime_sha": runtime_sha, "correlation_id": correlation,
        "session_id": session, "snapshot_sha256": snapshot,
        "run_id": run, "attempt": attempt, "workspace": workspace,
    }


def read_git(root: Path, *args: str) -> str:
    require(root.is_dir() and not root.is_symlink(),
            "issue8_pinned_checkout_missing")
    actions = {
        ("rev-parse", "HEAD"): "sha",
        ("status", "--porcelain", "--untracked-files=no"): "status",
    }
    action = actions.get(tuple(args))
    require(action is not None, "issue8_git_action_not_allowlisted")
    local_env = dict(os.environ)
    local_env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    try:
        r = subprocess.run(
            ["git", *args], cwd=root, env=local_env,
            capture_output=True, text=True, check=False, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightBlocked(f"issue8_git_{action}_unavailable") from None
    require(r.returncode == 0 and not r.stderr.strip()
            and len(r.stdout) <= 4096,
            f"issue8_git_{action}_invalid")
    return r.stdout.strip()


def canonical_git_source(worker: Path) -> bytes:
    """Return exact pinned Git blob bytes, not platform-converted checkout."""
    require(worker.is_dir() and not worker.is_symlink(),
            "issue8_pinned_checkout_missing")
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    argv = ["git", "show", "HEAD:" + SOURCE_PATH]
    try:
        result = subprocess.run(
            argv, cwd=worker, env=env, capture_output=True,
            text=False, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise PreflightBlocked("issue8_git_blob_unavailable") from None
    require(result.returncode == 0 and
            type(result.stdout) is bytes and
            type(result.stderr) is bytes and not result.stderr and
            0 < len(result.stdout) <= 262_144,
            "issue8_git_blob_invalid")
    raw = result.stdout
    blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()
    require(blob == SOURCE_BLOB_SHA, "issue8_source_blob_drift")
    return raw


def verify_pinned_checkout(env: dict[str, str], identity: dict[str, str]) -> tuple[Path, bytes]:
    workspace = Path(identity["workspace"]).resolve(strict=True)
    rules = workspace / "_rules"
    worker = workspace / "_worker_pool"
    host = Path(env.get("SESSION_TARGET_PATH", "")).resolve(strict=True)
    require(host.is_dir() and host != workspace
            and (host / "scripts" / "issue8_dell_rag_preflight.py").is_file(),
            "issue8_governed_worktree_invalid")
    for repo, pinned in (
        (host, identity["runtime_sha"]),
        (worker, WORKER_SHA),
        (rules, RULES_SHA),
    ):
        require(read_git(repo, "rev-parse", "HEAD") == pinned,
                "issue8_checkout_sha_drift")
        require(read_git(repo, "status", "--porcelain", "--untracked-files=no") == "",
                "issue8_checkout_dirty")
    source = worker / SOURCE_PATH
    require(source.is_file() and not source.is_symlink()
            and source.resolve().is_relative_to(worker.resolve()),
            "issue8_source_missing")
    # Git's object database is the canonical source. Git for Windows may
    # materialize LF blobs as CRLF files without marking the worktree dirty.
    # Never hash the checkout bytes and call them the Git blob.
    raw = canonical_git_source(worker)
    worktree = source.read_bytes()
    require(worktree == raw or (
                b"\r\n" not in raw and worktree == raw.replace(b"\n", b"\r\n")
            ), "issue8_checkout_bytes_drift")
    return worker, raw


def read_original_bytes(reader: object, path: str, sha: str) -> bytes:
    require(sha == WORKER_SHA and
            path in {"README.md", "AGENTS.md",
                     "docs/ISSUE_QWEN7B_DRAFT_HANDOFF.md"},
            "issue8_independent_path_invalid")
    try:
        obj = reader.get_text_file(WORKER_REPOSITORY, path, sha)
        require(type(obj) is dict and obj.get("type") == "file"
                and obj.get("path") == path
                and obj.get("encoding") == "base64"
                and type(obj.get("size")) is int
                and 0 < obj["size"] <= 65536
                and type(obj.get("content")) is str,
                "issue8_independent_blob_invalid")
        raw = base64.b64decode(
            obj["content"].replace("\n", ""), validate=True,
        )
        require(len(raw) == obj["size"], "issue8_independent_blob_invalid")
        require(hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
        ).hexdigest() == obj.get("sha"),
                "issue8_independent_blob_drift")
        return raw
    except PreflightBlocked:
        raise
    except Exception:
        raise PreflightBlocked("issue8_independent_api_unavailable") from None


def attest_issue_rag_receipt(receipt: object) -> None:
    """Distinguish trusted failure categories; never promote refusal to success.

    This only checks the *shape and process* of a real model result. Actual
    GitHub source bytes/citation are independently verified afterwards.
    """
    require(type(receipt) is dict, "issue8_rag_schema_invalid")
    require(receipt.get("schema_version") == "worker.rag.issue-context-v1"
            and receipt.get("issue_number") == ISSUE_NUMBER,
            "issue8_rag_identity_invalid")
    require(receipt.get("head_sha") == WORKER_SHA
            and receipt.get("base_sha") == WORKER_SHA,
            "issue8_rag_head_mismatch")
    require(receipt.get("state") == "supported",
            "issue8_rag_insufficient_evidence")
    require(receipt.get("model_process_verified") is True,
            "issue8_rag_model_process_unverified")
    require(receipt.get("issue_head_readback_stable") is True,
            "issue8_rag_source_readback_unverified")
    require(receipt.get("execution_authorized") is False
            and receipt.get("state_changed") is False,
            "issue8_rag_readonly_boundary_invalid")
    calls = receipt.get("model_calls")
    require(type(calls) is int and 2 <= calls <= 4,
            "issue8_rag_model_calls_invalid")


def run(env: dict[str, str]) -> dict[str, object]:
    _set_phase('identity')
    identity = validate_environment(env)
    _set_phase('checkouts')
    worker, original = verify_pinned_checkout(env, identity)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(worker))
    _set_phase('agent_core')
    agent = Path(identity["workspace"]) / "_agent_core"
    require(read_git(agent, "rev-parse", "HEAD")
            == "1fc032d4c412bdb4ed202cf1193caf0cb49490ce",
            "issue8_agent_core_sha_drift")
    sys.path.insert(0, str(agent))

    _set_phase('imports')
    from app.issue_draft_pr import admit, trusted_task
    from app.structured_code_worker import validate
    from app.issue_rag_research import official_issue_reader, research_issue
    from app.issue_rag_handoff import bind_issue_rag
    from app.native_structured_ollama import NativeStructuredOllama

    # Independent live GitHub read; no synthetic issue or pre-authorized JSON.
    _set_phase('owner')
    public_api = official_issue_reader(env.get("GITHUB_TOKEN") or None)
    now = datetime.now(timezone.utc)
    approved = admit(
        public_api.get_issue(ISSUE_NUMBER),
        public_api.get_comment(OWNER_COMMENT_ID),
        public_api.get_branch("main"),
        base_sha=WORKER_SHA,
        observed_at=now.isoformat(), now=now,
    )
    task = trusted_task(approved, original)
    _set_phase('baseline')
    baseline = validate(original.decode("utf-8"), task)
    require(type(baseline) is dict and baseline.get("total") == 42
            and type(baseline.get("passed")) is int
            and 0 <= baseline["passed"] < 42,
            "issue8_baseline_not_reproducible")

    # Real Ollama calls must occur ONLY after the above owner/HEAD/baseline
    # gates. NativeStructuredOllama checks GGUF digest and no cloud endpoints.
    _set_phase('model')
    NativeStructuredOllama.no_cloud()
    _set_phase('research')
    receipt = research_issue(approved, github_token=env.get("GITHUB_TOKEN") or None)
    attest_issue_rag_receipt(receipt)

    # Separate API client validates the exact cited bytes after inference.
    _set_phase('readback')
    independent = official_issue_reader(env.get("GITHUB_TOKEN") or None)
    citation = bind_issue_rag(
        approved, receipt,
        lambda path, sha: read_original_bytes(independent, path, sha),
    )
    current = independent.get_branch("main").get("commit", {}).get("sha")
    require(current == WORKER_SHA, "issue8_main_changed_after_rag")
    _, post_source = verify_pinned_checkout(env, identity)
    require(post_source == original, "issue8_worker_modified")
    result = {
        "result": "ISSUE8_NATIVE_RAG_PREFLIGHT_VERIFIED",
        "schema_version": "issue8.native.rag.readonly-v1",
        "issue_number": ISSUE_NUMBER,
        "worker_sha": WORKER_SHA,
        "runtime_sha": identity["runtime_sha"],
        "rules_sha": RULES_SHA,
        "model_calls": receipt["model_calls"],
        "model_digest_prefix": citation.model_digest[:12],
        "baseline_total": baseline["total"],
        "baseline_passed": baseline["passed"],
        "citation_path": citation.source_path,
        "citation_line": citation.line,
        "source_sha256": citation.source_sha256,
        "receipt_sha256": citation.receipt_sha256,
        "independent_git_source_readback": True,
        "session_result": "SESSION_LAUNCH_OK",
        "session_id": identity["session_id"],
        "snapshot_sha256": identity["snapshot_sha256"],
        "correlation_id": identity["correlation_id"],
        "run_id": identity["run_id"],
        "run_attempt": identity["attempt"],
        "state_changed": False,
        "cas_write": False,
        "draft_pr_created": False,
        "model_commands_authorized": False,
    }
    return result


def main() -> int:
    try:
        observed = run(dict(os.environ))
    except Exception as exc:
        code = (
            str(exc) if (
                (
                    type(exc) is PreflightBlocked or
                    (type(exc).__module__, type(exc).__name__) in {
                        ("app.issue_draft_pr", "HandoffBlocked"),
                        ("app.structured_code_worker", "StructuredBlocked"),
                        ("app.agent_rag_consumer", "ResearchBlocked"),
                        ("agent_core.contracts", "Blocked"),
                    }
                )
                and re.fullmatch(
                    r"(?:issue8_|rag_|main_|owner_|native_|github_|context_)[a-z0-9_]{2,95}",
                    str(exc),
                )
            )
            else "issue8_native_dependency_unavailable"
        )
        print(json.dumps({
            "result": "ISSUE8_NATIVE_RAG_PREFLIGHT_BLOCKED",
            "reason_code": code,
            "phase": _PHASE if _PHASE in _PHASES else "identity",
            "state_changed": False,
            "draft_pr_created": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(observed, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
