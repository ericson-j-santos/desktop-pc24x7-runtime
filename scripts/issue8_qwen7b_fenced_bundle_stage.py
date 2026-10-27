"""Issue #8: stage a REAL Ollama-generated Git bundle behind a local fenced lease.

This is a bounded physical BUILDER stage, NOT a completed production Worker Pool
task. The local SQLite authority is isolated; completing a distributed lease,
durable CAS publication, independent remote verification and PR draft are later
gates. No GitHub write credential, Docker, cloud inference, merge or deploy.

The outer GitHub Actions workflow must prove OWNER authorization for the current
Worker Pool SHA, and materialize the governed Dell Session Launcher worktree
BEFORE invoking this script through Command Gateway.
"""
from __future__ import annotations

from contextlib import contextmanager

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import traceback
from typing import Any, Callable

HOST = "DESKTOP-PDQK954"
RUNTIME = "ericson-j-santos/desktop-pc24x7-runtime"
WORKER = "ericson-j-santos/engineering-worker-pool"
ISSUE = 8
WORKER_SHA = "87a8de64ea5ed2e4aef1a9cde51861edb61ffe5e"
RUNTIME_SHA = "005cc39d38f90e5d7ae4b3f6e23d4e119ce4120f"
OWNER_COMMENT = 6430299388
PATH = "app/portfolio_bridge.py"
SOURCE_BLOB = "d9a25c574163c49f695e774609949160d94f4490"
MODEL = "qwen2.5-coder:7b"
MODEL_PREFIX = "dae161e27b0e"
RULES_SHA = "3ffb7d2ab3269fb75ed37b9abbc2de562d156098"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class IssueStageBlocked(RuntimeError):
    """Static sanitized error codes only."""


def require(value: Any, code: str) -> None:
    if not value:
        raise IssueStageBlocked(code)


def verified_bundle_receipt(report: dict[str, Any]) -> dict[str, Any]:
    """Validate the same output contract before any subsequent GitHub write."""
    require(type(report) is dict, "bundle_report_invalid")
    expected_keys = {
        "result", "issue", "source_repository", "base_sha", "produced_sha",
        "worker_pool_task_id", "owner_comment_id", "correlation_id",
        "model", "model_digest", "model_calls", "replay_model_calls",
        "before_sha256", "after_sha256", "patch_sha256", "bundle_sha256",
        "bundle_b64", "baseline_passed", "accepted_cases", "regressions_passed",
        "independent_checkout", "lease_generation", "fencing_required",
        "local_authority_only", "cas_persisted", "pr_created",
    }
    require(set(report) == expected_keys and report.get("result") ==
            "ISSUE8_BUNDLE_STAGED_UNPUBLISHED" and report.get("issue") == ISSUE
            and report.get("source_repository") == WORKER
            and report.get("base_sha") == WORKER_SHA
            and report.get("owner_comment_id") == OWNER_COMMENT
            and type(report.get("produced_sha")) is str
            and SHA40.fullmatch(report["produced_sha"]) is not None
            and report["produced_sha"] != WORKER_SHA
            and type(report.get("worker_pool_task_id")) is str
            and re.fullmatch(r"cwp-[0-9a-f]{24}", report["worker_pool_task_id"])
            and type(report.get("correlation_id")) is str
            and re.fullmatch(r"qwen7b-issue-8-[0-9a-f]{12}", report["correlation_id"])
            and report["model"] == MODEL
            and type(report.get("model_digest")) is str
            and SHA256.fullmatch(report["model_digest"]) is not None
            and report["model_digest"].startswith(MODEL_PREFIX)
            and type(report.get("model_calls")) is int
            and report["model_calls"] in (1, 2)
            and report.get("replay_model_calls") == 0
            and type(report.get("baseline_passed")) is int
            and 0 <= report["baseline_passed"] < 42
            and report.get("accepted_cases") == 42
            and type(report.get("regressions_passed")) is int
            and report["regressions_passed"] >= 52
            and report.get("independent_checkout") is True
            and type(report.get("lease_generation")) is int
            and report["lease_generation"] >= 1
            and report.get("fencing_required") is True
            and report.get("local_authority_only") is True
            and report.get("cas_persisted") is False
            and report.get("pr_created") is False,
            "bundle_report_identity_invalid")
    for key in ("before_sha256", "after_sha256", "patch_sha256", "bundle_sha256"):
        require(type(report.get(key)) is str
                and SHA256.fullmatch(report[key]) is not None,
                "bundle_digest_invalid")
    encoded = report.get("bundle_b64")
    require(type(encoded) is str and 0 < len(encoded) <= 131072
            and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", encoded) is not None,
            "bundle_encoding_invalid")
    try:
        blob = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise IssueStageBlocked("bundle_encoding_invalid") from None
    require(200 < len(blob) <= 96000
            and hashlib.sha256(blob).hexdigest() == report["bundle_sha256"]
            and base64.b64encode(blob).decode("ascii") == encoded,
            "bundle_bytes_unverified")
    return {**report, "bundle_bytes": len(blob)}



# Code-owned labels only; never disclose paths, secrets, model text or tracebacks.
CURRENT_PHASE = "entry"
_ALLOWED_PHASES = frozenset({
    "entry", "source_preflight", "builder_clone", "model_repair",
    "model_replay", "independent_validation", "source_integrity",
    "bundle_stage", "pool_state", "sandbox_teardown", "runner_output",
})
_ALLOWED_ERRORS = frozenset({
    "IssueStageBlocked", "StructuredBlocked", "PermissionError",
    "FileNotFoundError", "OSError", "RuntimeError", "ValueError",
    "TypeError", "KeyError", "AssertionError", "TimeoutExpired",
    "CalledProcessError", "NotADirectoryError",
})
_ALLOWED_SITES = frozenset({
    "issue8_qwen7b_fenced_bundle_stage.py", "tempfile.py", "shutil.py",
    "pathlib.py", "structured_code_worker.py", "native_structured_worker_e2e.py",
    "store.py", "issue_draft_pr.py", "native_structured_ollama.py",
})


def mark_phase(phase: str) -> None:
    global CURRENT_PHASE
    require(phase in _ALLOWED_PHASES, "diagnostic_phase_invalid")
    CURRENT_PHASE = phase


def sanitized_failure(exc: Exception) -> dict[str, Any]:
    """Retain evidence of the failure site, not its sensitive detail."""
    def category(problem: BaseException | None) -> str:
        candidate = type(problem).__name__ if problem is not None else "none"
        return candidate if candidate in _ALLOWED_ERRORS else "other"
    result: dict[str, Any] = {
        "failure_phase": CURRENT_PHASE if CURRENT_PHASE in _ALLOWED_PHASES else "entry",
        "exception_kind": category(exc),
        "masked_exception_kind": category(exc.__context__),
    }
    prior = exc.__context__
    if isinstance(prior, IssueStageBlocked):
        masked = str(prior)
        if re.fullmatch(r"[a-z][a-z0-9_]{2,80}", masked):
            result["masked_reason_code"] = masked
    try:
        for frame in reversed(traceback.extract_tb(exc.__traceback__)):
            basename = Path(frame.filename).name
            if basename in _ALLOWED_SITES and 0 < frame.lineno < 100000:
                result["failure_site"] = basename + ":" + str(frame.lineno)
                break
        worktree = Path(os.environ.get("SESSION_TARGET_PATH") or "/missing").resolve()
        if (worktree == Path.cwd().resolve()
                and "chatgpt-workers" in str(worktree).lower()
                and worktree.is_dir()):
            result["residual_sandbox_count"] = min(100, sum(
                1 for p in worktree.iterdir()
                if p.name.startswith("issue8-qwen-") and p.is_dir()
                and not p.is_symlink()
            ))
    except (OSError, ValueError, RuntimeError):
        result["diagnostic_readback"] = "unavailable"
    return result



@contextmanager
def governed_sandbox(target: Path):
    """Cleanup only this stage's temporary directory, with bounded lock recovery.

    Python TemporaryDirectory handles readonly Git files on Windows, but
    antivirus/filesystem locks may transiently deny unlink. Retry cleanup of
    the SAME generated directory, never ignore failure or touch other trees.
    """
    require(target.is_dir() and not target.is_symlink(),
            "sandbox_parent_unverified")
    holder = tempfile.TemporaryDirectory(prefix="issue8-qwen-", dir=target)
    sandbox = Path(holder.name).resolve()
    try:
        require(sandbox.parent == target
                and sandbox.name.startswith("issue8-qwen-")
                and sandbox.is_dir() and not sandbox.is_symlink(),
                "sandbox_boundary_invalid")
        yield sandbox
    finally:
        for attempt in range(3):
            try:
                holder.cleanup()
            except PermissionError:
                mark_phase("sandbox_teardown")
                if attempt == 2:
                    raise IssueStageBlocked("sandbox_cleanup_permission_denied") from None
                time.sleep((attempt + 1) * 0.5)
            except OSError:
                mark_phase("sandbox_teardown")
                raise
            else:
                break
        if sandbox.exists():
            mark_phase("sandbox_teardown")
            raise IssueStageBlocked("sandbox_cleanup_incomplete")


class _ClosingSQLiteHandle:
    """Close SQLite's native handle when exiting a transaction context."""
    def __init__(self, connection):
        self._connection = connection

    def __enter__(self):
        try:
            self._connection.__enter__()
        except BaseException:
            self._connection.close()
            raise
        return self._connection

    def __exit__(self, *exc):
        try:
            return self._connection.__exit__(*exc)
        finally:
            self._connection.close()

    def __getattr__(self, name):
        return getattr(self._connection, name)


def closing_worker_pool_type(base_store):
    """Preserve the pinned WorkerPoolStore logic, but close every read context."""
    class ScopedStore(base_store):
        def _db(self):
            return _ClosingSQLiteHandle(super()._db())
    return ScopedStore


def verified_final_checkouts(
    worker: Path, builder: Path, independent: Path, *,
    source_raw_sha256: str, produced_sha: str,
    git_read: Callable[..., str], source_clean: Callable[[Path], str],
) -> None:
    """Verify immutable source bytes and clean Git trees, not Git status mode labels.

    On Windows, Git can change the status classification between normalized
    CRLF and exact clean without changing HEAD, index or physical bytes.
    Never accept an actual byte, staged-index or untracked worktree change.
    """
    require(git_read(worker, "rev-parse", "HEAD") == WORKER_SHA,
            "source_head_changed")
    source_file = worker / PATH
    require(source_file.is_file() and not source_file.is_symlink(),
            "source_file_unavailable")
    require(hashlib.sha256(source_file.read_bytes()).hexdigest() == source_raw_sha256,
            "source_raw_bytes_changed")
    require(git_read(worker, "diff", "--cached", "--name-only", "HEAD", "--") == "",
            "source_index_changed")
    try:
        mode = source_clean(worker)
    except Exception as exc:
        code = str(exc)
        if code in ("source_tree_dirty", "source_blob_mismatch"):
            raise IssueStageBlocked(code) from None
        raise IssueStageBlocked("source_checkout_unverified") from None
    require(mode in ("exact_clean", "git_verified_crlf_normalization"),
            "source_checkout_unverified")
    for checkout, prefix in ((builder, "builder"), (independent, "validator")):
        require(git_read(checkout, "rev-parse", "HEAD") == produced_sha,
                prefix + "_head_changed")
        require(git_read(checkout, "status", "--porcelain", "--untracked-files=all") == "",
                prefix + "_checkout_dirty")


def execute() -> dict[str, Any]:
    mark_phase("source_preflight")
    env = os.environ
    require(os.name == "nt"
            and env.get("COMPUTERNAME", "").upper() == HOST
            and env.get("RUNNER_NAME") == "DESKTOP-PDQK954-runtime"
            and env.get("GITHUB_REPOSITORY") == RUNTIME
            and env.get("GITHUB_ACTIONS") == "true"
            and env.get("GITHUB_EVENT_NAME") == "pull_request"
            and env.get("GITHUB_ACTOR") == "ericson-j-santos"
            and env.get("NATIVE_OLLAMA_DEV") == "1"
            and env.get("NATIVE_MODEL_DIGEST_PREFIX") == MODEL_PREFIX
            and env.get("EXPECTED_WORKER_SHA") == WORKER_SHA
            and env.get("RULES_SHA") == RULES_SHA
            and env.get("SESSION_LAUNCH_RESULT") == "SESSION_LAUNCH_OK"
            and env.get("SESSION_STATE_VALIDATED") == "true",
            "physical_admission_unverified")
    target = Path(env.get("SESSION_TARGET_PATH") or "/not-a-worktree").resolve()
    source = Path(env.get("GITHUB_WORKSPACE") or "/no-workspace").resolve()
    require(target.is_dir() and "chatgpt-workers" in str(target).lower()
            and target == Path.cwd().resolve() and target != source,
            "governed_worktree_invalid")
    worker = (source / "external" / "engineering-worker-pool").resolve()
    require(worker.is_dir() and worker != target and not worker.is_symlink(),
            "worker_checkout_missing")

    if str(worker) not in sys.path:
        sys.path.insert(0, str(worker))
    from app.issue_draft_pr import IssueBinding, trusted_task
    from app.native_structured_ollama import NativeStructuredOllama
    from app.structured_code_worker import git, repair, validate, sha256
    from app.store import WorkerPoolStore
    from scripts.native_structured_worker_e2e import (
        verified_source_clean, preflight_bridge_regressions, run_bridge_regressions,
    )

    require(git(worker, "rev-parse", "HEAD") == WORKER_SHA
            and git(worker, "rev-parse", "HEAD:" + PATH) == SOURCE_BLOB,
            "worker_sha_or_blob_changed")
    verified_source_clean(worker)
    source_raw_sha256 = sha256((worker / PATH).read_bytes())
    binding = IssueBinding(
        number=ISSUE, base_sha=WORKER_SHA, comment_id=OWNER_COMMENT,
        request_id="issue-" + hashlib.sha256(
            (WORKER + "#8:bridge.property.v1:" + WORKER_SHA).encode()
        ).hexdigest(),
        correlation_id="qwen7b-issue-8-" + WORKER_SHA[:12],
        branch="agent/qwen7b-issue-8-" + WORKER_SHA[:12],
    )
    with governed_sandbox(target) as sandbox:
        builder = sandbox / "builder"
        independent = sandbox / "validator"
        state = sandbox / "repair-state"
        # Force canonical Git LF materialization on Windows. Hashes in
        # cross-host CAS receipts must match the blob bytes on hosted Linux.
        # A process-scoped -c affects checkout LF without persisting the
        # setting in .git/config (the structured worker forbids that key).
        mark_phase("builder_clone")
        git(sandbox, "-c", "core.autocrlf=false", "clone",
            "--no-hardlinks", str(worker), str(builder))
        git(builder, "remote", "remove", "origin")
        git(builder, "switch", "-c", "worker/issue8-qwen")
        require(git(builder, "rev-parse", "HEAD") == WORKER_SHA
                and git(builder, "rev-parse", "HEAD:" + PATH) == SOURCE_BLOB,
                "builder_sha_drift")
        before = (builder / PATH).read_bytes()
        task = trusted_task(binding, before)
        baseline = validate(before.decode("utf-8"), task)
        require(baseline["total"] == 42 and baseline["passed"] < 42,
                "no_real_baseline_failure")
        regression_preflight = preflight_bridge_regressions(builder, sandbox)
        require(regression_preflight.get("collected_count", 0) >= 52,
                "regression_preflight_insufficient")
        # This is a REAL isolated WorkerPoolStore and fenced lease. It is NOT
        # the always-on shared DEV authority, hence cannot prove cross-job lease
        # completion. The task is intentionally left running/staged.
        pool = closing_worker_pool_type(WorkerPoolStore)(sandbox / "worker.db",
                               expected_rules_sha=RULES_SHA,
                               default_lease_seconds=300)
        pool.enable_fenced_cutover(
            correlation_id=binding.correlation_id,
            legacy_claimers_drained=True, shared_queue_exclusive=True,
        )
        pool.configure_repository(repository=WORKER, enabled=True,
                                  max_in_flight=1)
        pool.register_worker(
            worker_id="issue8-qwen7b-builder", host=HOST, role="builder",
            profile="NORMAL", correlation_id=binding.correlation_id,
            rules_sha=RULES_SHA, gateway_ok=True, state_validated=True,
            worktree_root=str(target),
        )
        queued, created = pool.enqueue_task(
            repository=WORKER, issue_number=ISSUE,
            request_id=binding.request_id,
            correlation_id=binding.correlation_id,
            base_sha=WORKER_SHA, target_branch=binding.branch,
            max_attempts=2, fencing_required=True,
        )
        require(created is True and queued["state"] == "queued"
                and queued["base_sha"] == WORKER_SHA,
                "fenced_task_not_created")
        claimed, lease = pool.claim_task(
            worker_id="issue8-qwen7b-builder", role="builder",
            correlation_id=binding.correlation_id, lease_seconds=300,
            only_task_id=queued["task_id"], fencing_required=True,
        )
        require(lease is not None and claimed is not None
                and claimed["task_id"] == queued["task_id"]
                and claimed["fencing_required"] == 1
                and lease.lease_generation == 1
                and lease.role == "builder",
                "fenced_lease_not_acquired")
        pool.start_task(
            task_id=queued["task_id"], worker_id=lease.worker_id,
            lease_token=lease.lease_token,
            lease_generation=lease.lease_generation,
            attempt_id=lease.attempt_id,
            correlation_id=binding.correlation_id,
        )
        # task_id is the real existing pool ID, not a new queue.
        task["task_id"] = queued["task_id"]
        mark_phase("model_repair")
        provider = NativeStructuredOllama()
        result = repair(builder, state, task, provider)
        require(provider.process_verified is True
                and provider.model_digest.startswith(MODEL_PREFIX)
                and result["model_calls"] in (1, 2)
                and result["produced_sha"] != WORKER_SHA,
                "native_model_inference_not_verified")
        mark_phase("model_replay")
        replay = repair(builder, state, task, provider)
        require(replay.get("replayed") is True
                and replay.get("model_calls") == 0
                and replay.get("produced_sha") == result["produced_sha"],
                "no_inference_replay_not_proved")
        mark_phase("independent_validation")
        git(sandbox, "-c", "core.autocrlf=false", "clone",
            "--no-hardlinks", str(builder), str(independent))
        git(independent, "remote", "remove", "origin")
        git(independent, "checkout", "--detach", result["produced_sha"])
        after = (independent / PATH).read_bytes()
        validation = validate(after.decode("utf-8"), task)
        require(validation["passed"] == validation["total"] == 42
                and validation["errors"] == 0
                and result["validation"] == validation
                and sha256(after) == result["after_sha256"]
                and git(independent, "rev-parse", "HEAD") == result["produced_sha"]
                and git(independent, "diff", "--name-only",
                        WORKER_SHA, result["produced_sha"]) == PATH,
                "independent_content_or_scope_failed")
        regressions = run_bridge_regressions(independent, sandbox)
        require(regressions.get("category") == "passed"
                and regressions.get("exit_code") == 0
                and regressions.get("passed_count", 0) >= 52
                and regressions.get("failed_count") == 0
                and regressions.get("error_count") == 0,
                "independent_regressions_failed")
        mark_phase("source_integrity")
        verified_final_checkouts(
            worker, builder, independent,
            source_raw_sha256=source_raw_sha256,
            produced_sha=result["produced_sha"],
            git_read=git, source_clean=verified_source_clean,
        )
        mark_phase("bundle_stage")
        bundle = sandbox / "change.bundle"
        git(builder, "bundle", "create", str(bundle), "HEAD",
            "^" + WORKER_SHA)
        bundle_bytes = bundle.read_bytes()
        require(200 < len(bundle_bytes) <= 96000, "bundle_size_out_of_bounds")
        git(worker, "bundle", "verify", str(bundle))
        staged = {
            "result": "ISSUE8_BUNDLE_STAGED_UNPUBLISHED",
            "issue": ISSUE, "source_repository": WORKER,
            "base_sha": WORKER_SHA, "produced_sha": result["produced_sha"],
            "worker_pool_task_id": queued["task_id"],
            "owner_comment_id": OWNER_COMMENT,
            "correlation_id": binding.correlation_id,
            "model": MODEL, "model_digest": provider.model_digest,
            "model_calls": result["model_calls"],
            "replay_model_calls": replay["model_calls"],
            "before_sha256": result["before_sha256"],
            "after_sha256": result["after_sha256"],
            "patch_sha256": result["patch_sha256"],
            "bundle_sha256": sha256(bundle_bytes),
            "bundle_b64": base64.b64encode(bundle_bytes).decode("ascii"),
            "baseline_passed": baseline["passed"],
            "accepted_cases": validation["passed"],
            "regressions_passed": regressions["passed_count"],
            "independent_checkout": True,
            "lease_generation": lease.lease_generation,
            "fencing_required": True, "local_authority_only": True,
            "cas_persisted": False, "pr_created": False,
        }
        verified_bundle_receipt(staged)
        mark_phase("pool_state")
        current = pool.get_task(queued["task_id"])
        require(current["state"] == "running"
                and current["task_id"] == queued["task_id"]
                and current["builder_worker_id"] == lease.worker_id
                and current["fencing_required"] == 1
                and current["produced_sha"] is None,
                "local_pool_staged_state_invalid")
        # Transport the already verified Git bundle before Windows teardown.
        # Failure of teardown still blocks the approved CAS/Validator/PR path;
        # only a separate hosted quarantine may retain this evidence.
        mark_phase("runner_output")
        _publish_github_step_outputs(staged)
        mark_phase("sandbox_teardown")
        return staged


def _publish_github_step_outputs(report: dict[str, Any]) -> None:
    """Runner-owned IPC only; bytes are public Git objects, never credentials."""
    verified_bundle_receipt(report)
    output = os.environ.get("GITHUB_OUTPUT", "")
    runner_temp = os.environ.get("RUNNER_TEMP", "")
    require(bool(output and runner_temp), "github_output_ipc_missing")
    dest = Path(output).resolve()
    temp = Path(runner_temp).resolve()
    require(dest.is_file() and not dest.is_symlink()
            and dest.name.startswith("set_output_")
            and dest.is_relative_to(temp) and temp.is_dir(),
            "github_output_destination_untrusted")
    summary = {k: v for k, v in report.items() if k != "bundle_b64"}
    encoded = base64.b64encode(json.dumps(
        summary, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")).decode("ascii")
    with dest.open("a", encoding="ascii", newline="\n") as stream:
        stream.write("bundle_b64=" + report["bundle_b64"] + "\n")
        stream.write("receipt_b64=" + encoded + "\n")


def main() -> int:
    sys.dont_write_bytecode = True
    mark_phase("entry")
    try:
        result = execute()
        # Runner output was emitted only after validation, before sandbox cleanup.
        # Never write binary/base64 model artifacts or credentials to logs.
        summary = {k: v for k, v in result.items() if k != "bundle_b64"}
        print(json.dumps(summary, ensure_ascii=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        raw = str(exc)
        reason = (raw if isinstance(exc, IssueStageBlocked)
                  and re.fullmatch(r"[a-z][a-z0-9_]{2,80}", raw)
                  else "physical_issue_stage_unverified")
        print(json.dumps({
            "result": "ISSUE8_BUNDLE_STAGE_BLOCKED", "reason_code": reason,
            "model_output_published": False, "cas_persisted": False,
            "draft_pr_created": False,
            **sanitized_failure(exc),
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
