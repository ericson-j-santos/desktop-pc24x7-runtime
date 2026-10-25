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

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

HOST = "DESKTOP-PDQK954"
RUNTIME = "ericson-j-santos/desktop-pc24x7-runtime"
WORKER = "ericson-j-santos/engineering-worker-pool"
ISSUE = 8
WORKER_SHA = "21fd68dec6f0da92b3e7da201463401ac5429d64"
RUNTIME_SHA = "a0437b0deb7db42fb91866fe8e77359844579cf6"
OWNER_COMMENT = 6399359287
PATH = "app/portfolio_bridge.py"
SOURCE_BLOB = "d9a25c574163c49f695e774609949160d94f4490"
MODEL = "qwen2.5-coder:7b"
MODEL_PREFIX = "dae161e27b0e"
RULES_SHA = "4e6091a133f8d7d157abe6f83c31ca597812e0a4"
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


def execute() -> dict[str, Any]:
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
    source_mode = verified_source_clean(worker)
    binding = IssueBinding(
        number=ISSUE, base_sha=WORKER_SHA, comment_id=OWNER_COMMENT,
        request_id="issue-" + hashlib.sha256(
            (WORKER + "#8:bridge.property.v1:" + WORKER_SHA).encode()
        ).hexdigest(),
        correlation_id="qwen7b-issue-8-" + WORKER_SHA[:12],
        branch="agent/qwen7b-issue-8-" + WORKER_SHA[:12],
    )
    before = (worker / PATH).read_bytes()
    task = trusted_task(binding, before)
    baseline = validate(before.decode("utf-8"), task)
    require(baseline["total"] == 42 and baseline["passed"] < 42,
            "no_real_baseline_failure")
    with tempfile.TemporaryDirectory(prefix="issue8-qwen-", dir=target) as location:
        sandbox = Path(location)
        builder = sandbox / "builder"
        independent = sandbox / "validator"
        state = sandbox / "repair-state"
        git(sandbox, "clone", "--no-hardlinks", str(worker), str(builder))
        git(builder, "remote", "remove", "origin")
        git(builder, "switch", "-c", "worker/issue8-qwen")
        require(git(builder, "rev-parse", "HEAD") == WORKER_SHA,
                "builder_sha_drift")
        regression_preflight = preflight_bridge_regressions(builder, sandbox)
        require(regression_preflight.get("collected_count", 0) >= 52,
                "regression_preflight_insufficient")
        # This is a REAL isolated WorkerPoolStore and fenced lease. It is NOT
        # the always-on shared DEV authority, hence cannot prove cross-job lease
        # completion. The task is intentionally left running/staged.
        pool = WorkerPoolStore(sandbox / "worker.db",
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
        provider = NativeStructuredOllama()
        result = repair(builder, state, task, provider)
        require(provider.process_verified is True
                and provider.model_digest.startswith(MODEL_PREFIX)
                and result["model_calls"] in (1, 2)
                and result["produced_sha"] != WORKER_SHA,
                "native_model_inference_not_verified")
        replay = repair(builder, state, task, provider)
        require(replay.get("replayed") is True
                and replay.get("model_calls") == 0
                and replay.get("produced_sha") == result["produced_sha"],
                "no_inference_replay_not_proved")
        git(sandbox, "clone", "--no-hardlinks", str(builder), str(independent))
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
        require(git(worker, "rev-parse", "HEAD") == WORKER_SHA
                and verified_source_clean(worker) == source_mode
                and git(builder, "status", "--porcelain") == ""
                and git(independent, "status", "--porcelain") == "",
                "source_integrity_lost")
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
        current = pool.get_task(queued["task_id"])
        require(current["state"] == "running"
                and current["task_id"] == queued["task_id"]
                and current["builder_worker_id"] == lease.worker_id
                and current["fencing_required"] == 1
                and current["produced_sha"] is None,
                "local_pool_staged_state_invalid")
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
    with dest.open("a", encoding="ascii", newline="\\n") as stream:
        stream.write("bundle_b64=" + report["bundle_b64"] + "\\n")
        stream.write("receipt_b64=" + encoded + "\\n")


def main() -> int:
    sys.dont_write_bytecode = True
    try:
        result = execute()
        _publish_github_step_outputs(result)
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
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
