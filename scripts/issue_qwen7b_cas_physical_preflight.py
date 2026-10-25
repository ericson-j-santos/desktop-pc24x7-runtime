"""Issue #8: on-Desktop GitHub CAS write/readback preflight (no inference).

Must run inside an already materialized Session Launcher + Command Gateway
risk-2 execution. Uses pinned Worker Pool code and a private, independently
provisioned GitHub token FILE. No Docker, model pull, merge, deployment, generic
commands or fallback for missing credentials.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

HOST = "DESKTOP-PDQK954"
RUNTIME_REPO = "ericson-j-santos/desktop-pc24x7-runtime"
WORKER_REPO = "ericson-j-santos/engineering-worker-pool"
EXPECTED_ISSUE = 8
OWNER_COMMENT_ID = 6393288083
BASE_SHA = "2eebbc18d115cada66ccf13c00dc4687cc77abba"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class PreflightBlocked(RuntimeError):
    """Sanitized error code, never file contents, provider body or secrets."""


def require(ok: Any, code: str) -> None:
    if not ok:
        raise PreflightBlocked(code)


def _git(root: Path, *args: str) -> str:
    try:
        call = subprocess.run(
            ["git", *args], cwd=root, text=True, capture_output=True,
            timeout=15, check=False,
            env={"PATH": os.environ.get("PATH", os.defpath),
                 "GIT_CONFIG_GLOBAL": os.devnull,
                 "GIT_CONFIG_SYSTEM": os.devnull,
                 "GIT_TERMINAL_PROMPT": "0"},
        )
    except (subprocess.TimeoutExpired, OSError):
        raise PreflightBlocked("read_only_git_unavailable") from None
    require(call.returncode == 0 and len(call.stdout) <= 4096,
            "read_only_git_failed")
    return call.stdout.strip().lower()


def gate_preflight(
    *, issue_result: Callable[[], dict[str, Any]],
    model_result: Callable[[], dict[str, Any]],
    cas_preflight: Callable[[], None],
    cas_readback: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Pure orchestration; only the installed CAS port may do the write.

    These callbacks are trusted versioned dependencies, never issue text.
    Unit tests with fake callbacks establish control logic, not physical proof.
    """
    issue = issue_result()
    require(type(issue) is dict
            and issue.get("issue") == EXPECTED_ISSUE
            and issue.get("base_sha") == BASE_SHA
            and issue.get("owner_verified") is True
            and type(issue.get("baseline_passed")) is int
            and 0 <= issue["baseline_passed"] < 42
            and issue.get("cases_total") == 42
            and type(issue.get("source_sha256")) is str
            and SHA256.fullmatch(issue["source_sha256"]) is not None,
            "issue_authorization_or_baseline_missing")
    model = model_result()
    require(type(model) is dict
            and model.get("model") == "qwen2.5-coder:7b"
            and type(model.get("digest")) is str
            and SHA256.fullmatch(model["digest"]) is not None
            and model["digest"].startswith("dae161e27b0e")
            and model.get("local_only") is True
            and model.get("model_calls") == 0,
            "local_qwen_readiness_unproved")
    cas_preflight()
    readback = cas_readback()
    require(type(readback) is dict
            and readback.get("sha256_verified") is True
            and readback.get("issue_scoped") is True
            and type(readback.get("branch_sha")) is str
            and SHA40.fullmatch(readback["branch_sha"]) is not None
            and readback["branch_sha"] != BASE_SHA
            and type(readback.get("object_sha256")) is str
            and SHA256.fullmatch(readback["object_sha256"]) is not None,
            "remote_cas_readback_unproved")
    return {
        "result": "ISSUE_QWEN7B_CAS_PREFLIGHT_PASSED",
        "issue": EXPECTED_ISSUE, "base_sha": BASE_SHA,
        "source_sha256": issue["source_sha256"],
        "baseline_passed": issue["baseline_passed"],
        "cases_total": 42, "model": model["model"],
        "model_digest_prefix": model["digest"][:12],
        "model_calls": 0,
        "cas_branch_sha": readback["branch_sha"],
        "cas_object_sha256": readback["object_sha256"],
        "cas_independent_readback": True,
        "patch_produced": False, "worker_claimed": False,
        "pr_created": False, "merge_performed": False,
        "production_touched": False, "docker_used": False,
    }


def execute() -> dict[str, Any]:
    # This is NOT a session bootstrap. Its caller must have passed one.
    environment = os.environ
    require(os.name == "nt" and environment.get("COMPUTERNAME", "").upper() == HOST
            and environment.get("RUNNER_NAME") == "DESKTOP-PDQK954-runtime"
            and environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("GITHUB_REPOSITORY") == RUNTIME_REPO
            and environment.get("GITHUB_EVENT_NAME") == "pull_request"
            and environment.get("GITHUB_ACTOR") == "ericson-j-santos",
            "host_or_workflow_not_authorized")
    workspace = Path(environment.get("GITHUB_WORKSPACE", "")).resolve()
    target = Path(environment.get("SESSION_TARGET_PATH", "")).resolve()
    runtime_sha = environment.get("EXPECTED_RUNTIME_SHA", "")
    worker_sha = environment.get("EXPECTED_WORKER_SHA", "")
    require(bool(SHA40.fullmatch(runtime_sha))
            and bool(SHA40.fullmatch(worker_sha))
            and workspace.is_dir() and target.is_dir()
            and workspace != target
            and "chatgpt-workers" in str(target).lower()
            and Path.cwd().resolve() == target
            and _git(target, "rev-parse", "HEAD") == runtime_sha,
            "governed_worktree_not_attested")
    worker_root = (workspace / "external" / "engineering-worker-pool").resolve()
    require(worker_root.is_dir() and not worker_root.is_symlink()
            and worker_root != target
            and _git(worker_root, "rev-parse", "HEAD") == worker_sha,
            "worker_source_sha_mismatch")
    gh_token_file = environment.get("PORTFOLIO_GITHUB_TOKEN_FILE", "")
    require(bool(gh_token_file), "github_private_token_reference_missing")
    # Installed/pinned checkout is the sole provider of issue/CAS/model logic.
    sys.dont_write_bytecode = True
    if str(worker_root) not in sys.path:
        sys.path.insert(0, str(worker_root))
    import httpx  # type: ignore
    from app.github_draft_port import OfficialGitHubDraftPort
    from app.github_cas_transport import governed_bundle_transport
    from app.issue_draft_pr import admit, trusted_task, sha256
    from app.local_code_worker import OLLAMA_URL
    from app.native_structured_ollama import NativeStructuredOllama
    from app.structured_code_worker import validate
    from app.s3_git_bundle_artifact import PREFLIGHT_VALUE
    from scripts.native_structured_worker_e2e import verified_source_clean

    verified_source_clean(worker_root)
    port = OfficialGitHubDraftPort(token_file=Path(gh_token_file))
    try:
        now = datetime.now(timezone.utc)
        main = port.get_branch("main")
        require(type(main) is dict and main.get("commit", {}).get("sha") == BASE_SHA,
                "issue_main_sha_drift")
        binding = admit(
            port.get_issue(EXPECTED_ISSUE),
            port.get_comment(OWNER_COMMENT_ID),
            main, base_sha=BASE_SHA, observed_at=now.isoformat(), now=now,
        )
        before, blob = port.get_source(BASE_SHA)
        require(type(blob) is str and SHA40.fullmatch(blob) is not None,
                "source_blob_missing")
        task = trusted_task(binding, before)
        report = validate(before.decode("utf-8"), task)

        def issue_result():
            return {
                "issue": binding.number, "base_sha": binding.base_sha,
                "owner_verified": True, "baseline_passed": report["passed"],
                "cases_total": report["total"],
                "source_sha256": sha256(before),
            }

        def model_result():
            provider = NativeStructuredOllama()
            provider.no_cloud()
            with httpx.Client(
                base_url=OLLAMA_URL, timeout=8, trust_env=False,
                follow_redirects=False,
            ) as client:
                models = provider.request(client, "GET", "/api/tags").get("models")
            chosen = provider.select_model(models)
            return {
                "model": chosen["name"], "digest": chosen["digest"],
                "local_only": True, "model_calls": 0,
            }

        transport = governed_bundle_transport(port, binding)
        digest = hashlib.sha256(PREFLIGHT_VALUE).hexdigest()
        key = (transport.config.key_prefix
               + "/preflight-v1/sha256/" + digest[:2]
               + "/" + digest + ".probe")

        def cas_readback():
            item = transport.client.get_object(
                Bucket=transport.config.bucket, Key=key,
            )
            raw = item["Body"].read()
            b = transport.client._branch()
            return {
                "sha256_verified": raw == PREFLIGHT_VALUE
                and hashlib.sha256(raw).hexdigest() == digest,
                "issue_scoped": b is not None
                and transport.client.branch
                == f"agent/cas-qwen7b-issue-{binding.number}-{BASE_SHA[:12]}",
                "branch_sha": b["commit"]["sha"] if b else "",
                "object_sha256": digest,
            }

        result = gate_preflight(
            issue_result=issue_result,
            model_result=model_result,
            cas_preflight=transport.preflight,
            cas_readback=cas_readback,
        )
        require(_git(target, "rev-parse", "HEAD") == runtime_sha
                and _git(worker_root, "rev-parse", "HEAD") == worker_sha
                and port.get_branch("main")["commit"]["sha"] == BASE_SHA,
                "source_integrity_changed_after_probe")
        return {**result, "host": HOST, "runtime_sha": runtime_sha,
                "worker_sha": worker_sha}
    finally:
        port.close()


def main() -> int:
    sys.dont_write_bytecode = True
    try:
        print(json.dumps(execute(), sort_keys=True))
        return 0
    except Exception as exc:
        allowed_modules = {__name__, "app.issue_draft_pr",
                           "app.native_structured_ollama",
                           "app.structured_code_worker",
                           "app.native_one_shot"}
        raw = str(exc)
        code = (raw if type(exc).__module__ in allowed_modules
                and re.fullmatch(r"[a-z][a-z0-9_]{0,90}", raw)
                else "native_issue_cas_preflight_unavailable")
        print(json.dumps({
            "result": "ISSUE_QWEN7B_CAS_PREFLIGHT_BLOCKED",
            "reason_code": code, "production_touched": False,
            "model_calls": 0, "pr_created": False,
        }, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
