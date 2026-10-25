"""Hosted independent validator for one physically generated Qwen7B bundle.

Uses a different GitHub runner/checkout from the Dell Builder and validates
real Git commit ancestry, source integrity, the fixed 42 acceptance cases and
at least 52 current bridge regression tests. No GitHub write privileges.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

BASE = "21fd68dec6f0da92b3e7da201463401ac5429d64"
SOURCE_BLOB = "d9a25c574163c49f695e774609949160d94f4490"
PATH = "app/portfolio_bridge.py"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class ValidationBlocked(RuntimeError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValidationBlocked(reason)


def git(root: Path, *parts: str) -> str:
    try:
        p = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null",
             "-c", "protocol.file.allow=always", *parts],
            cwd=root, text=True, capture_output=True, timeout=50,
            check=False, env={
                "PATH": os.environ.get("PATH", os.defpath),
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ALLOW_PROTOCOL": "file",
                "LC_ALL": "C",
            },
        )
    except (subprocess.TimeoutExpired, OSError):
        raise ValidationBlocked("validator_git_unavailable") from None
    require(p.returncode == 0 and len(p.stdout) < 1_000_000
            and len(p.stderr) < 1_000_000, "validator_git_failed")
    return p.stdout.strip()


def validate_receipt(receipt: dict, bundle: bytes) -> None:
    """No self-supplied receipt can bypass the independent Git checks."""
    require(type(receipt) is dict
            and receipt.get("result") == "ISSUE8_BUNDLE_STAGED_UNPUBLISHED"
            and receipt.get("issue") == 8
            and receipt.get("source_repository") ==
            "ericson-j-santos/engineering-worker-pool"
            and receipt.get("base_sha") == BASE
            and receipt.get("owner_comment_id") == 6399359287
            and type(receipt.get("produced_sha")) is str
            and HEX40.fullmatch(receipt["produced_sha"]) is not None
            and receipt["produced_sha"] != BASE
            and receipt.get("model") == "qwen2.5-coder:7b"
            and type(receipt.get("model_digest")) is str
            and HEX64.fullmatch(receipt["model_digest"]) is not None
            and receipt["model_digest"].startswith("dae161e27b0e")
            and type(receipt.get("model_calls")) is int
            and receipt["model_calls"] in (1, 2)
            and receipt.get("replay_model_calls") == 0
            and receipt.get("independent_checkout") is True
            and receipt.get("fencing_required") is True
            and receipt.get("local_authority_only") is True
            and receipt.get("cas_persisted") is False
            and receipt.get("pr_created") is False
            and type(receipt.get("baseline_passed")) is int
            and 0 <= receipt["baseline_passed"] < 42
            and receipt.get("accepted_cases") == 42
            and type(receipt.get("regressions_passed")) is int
            and receipt["regressions_passed"] >= 52
            and type(receipt.get("worker_pool_task_id")) is str
            and re.fullmatch(r"cwp-[0-9a-f]{24}",
                             receipt["worker_pool_task_id"]) is not None,
            "validator_receipt_identity_invalid")
    for k in ("before_sha256", "after_sha256",
              "patch_sha256", "bundle_sha256"):
        require(type(receipt.get(k)) is str
                and HEX64.fullmatch(receipt[k]) is not None,
                "validator_digest_schema_invalid")
    require(type(bundle) is bytes and 200 < len(bundle) <= 96000
            and hashlib.sha256(bundle).hexdigest() ==
            receipt["bundle_sha256"],
            "validator_bundle_digest_invalid")


def execute(*, bundle_path: Path, receipt_base64: str,
            source_root: Path) -> dict:
    require(os.name != "nt" and source_root.is_dir()
            and bundle_path.is_file() and not bundle_path.is_symlink(),
            "validator_host_or_files_missing")
    require(type(receipt_base64) is str and 0 < len(receipt_base64) < 8192
            and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}",
                             receipt_base64) is not None,
            "validator_receipt_encoding_invalid")
    try:
        receipt = json.loads(base64.b64decode(
            receipt_base64, validate=True))
    except (ValueError, TypeError):
        raise ValidationBlocked("validator_receipt_encoding_invalid") from None
    raw = bundle_path.read_bytes()
    validate_receipt(receipt, raw)
    require(git(source_root, "rev-parse", "HEAD") == BASE
            and git(source_root, "rev-parse", "HEAD:" + PATH) == SOURCE_BLOB,
            "validator_source_baseline_changed")
    original = (source_root / PATH).read_bytes()
    require(hashlib.sha256(original).hexdigest() ==
            receipt["before_sha256"],
            "validator_before_content_mismatch")
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from app.issue_draft_pr import IssueBinding, trusted_task
    from app.structured_code_worker import validate
    from scripts.native_structured_worker_e2e import (
        run_bridge_regressions, preflight_bridge_regressions,
    )
    binding = IssueBinding(
        8, BASE, 6399359287,
        "issue-" + hashlib.sha256(
            ("ericson-j-santos/engineering-worker-pool#8:"
             "bridge.property.v1:" + BASE).encode()
        ).hexdigest(),
        "qwen7b-issue-8-" + BASE[:12],
        "agent/qwen7b-issue-8-" + BASE[:12],
    )
    task = trusted_task(binding, original)
    task["task_id"] = receipt["worker_pool_task_id"]
    baseline = validate(original.decode("utf8"), task)
    require(baseline["passed"] == receipt["baseline_passed"]
            and baseline["total"] == 42, "validator_baseline_mismatch")
    with tempfile.TemporaryDirectory(prefix="issue8-independent-") as d:
        root = Path(d)
        independent = root / "validator"
        git(root, "clone", "--no-hardlinks", str(source_root),
            str(independent))
        git(independent, "remote", "remove", "origin")
        git(independent, "bundle", "verify", str(bundle_path))
        git(independent, "fetch", "--no-tags", str(bundle_path), "HEAD")
        git(independent, "checkout", "--detach",
            receipt["produced_sha"])
        require(git(independent, "rev-parse", "HEAD") ==
                receipt["produced_sha"]
                and git(independent, "rev-list", "--parents", "-n", "1",
                        receipt["produced_sha"]) ==
                receipt["produced_sha"] + " " + BASE
                and git(independent, "rev-list", "--count",
                        BASE + ".." + receipt["produced_sha"]) == "1"
                and git(independent, "diff", "--name-only", BASE,
                        receipt["produced_sha"]) == PATH
                and git(independent, "status", "--porcelain") == "",
                "validator_git_commit_or_scope_invalid")
        after = (independent / PATH).read_bytes()
        require(after != original
                and hashlib.sha256(after).hexdigest() ==
                receipt["after_sha256"],
                "validator_after_bytes_invalid")
        case = validate(after.decode("utf-8"), task)
        require(case == {"passed": 42, "total": 42,
                         "errors": 0, "failures": []},
                "validator_acceptance_failed")
        before_tests = preflight_bridge_regressions(independent, root)
        regression = run_bridge_regressions(independent, root)
        require(before_tests["collected_count"] >= 52
                and regression["passed_count"] >= 52
                and regression["failed_count"] == 0
                and regression["error_count"] == 0
                and regression["exit_code"] == 0
                and regression["category"] == "passed",
                "validator_regression_failed")
        patch = git(independent, "diff", BASE,
                    receipt["produced_sha"], "--", PATH) + "\n"
        require(hashlib.sha256(patch.encode("utf8")).hexdigest() ==
                receipt["patch_sha256"],
                "validator_patch_digest_invalid")
        require(git(source_root, "rev-parse", "HEAD") == BASE
                and git(source_root, "rev-parse", "HEAD:" + PATH) == SOURCE_BLOB,
                "validator_source_integrity_lost")
        return {
            "result": "ISSUE8_INDEPENDENT_BUNDLE_VERIFIED",
            "issue": 8, "base_sha": BASE,
            "produced_sha": receipt["produced_sha"],
            "before_sha256": receipt["before_sha256"],
            "after_sha256": receipt["after_sha256"],
            "patch_sha256": receipt["patch_sha256"],
            "bundle_sha256": receipt["bundle_sha256"],
            "model": receipt["model"],
            "model_digest": receipt["model_digest"],
            "model_calls": receipt["model_calls"],
            "regressions_passed": regression["passed_count"],
            "cases_passed": case["passed"],
            "independent_host": "github-hosted-linux",
            "durable_cas_readback": True,
            "worker_pool_authority_completed": False,
            "ready_for_pr": False,
            "draft_pr_created": False,
        }


def main() -> int:
    try:
        value = execute(
            bundle_path=Path(os.environ.get("CWP_BUNDLE_FILE", "")),
            receipt_base64=os.environ.get("CWP_RECEIPT_B64", ""),
            source_root=Path(os.environ.get("CWP_WORKER_SOURCE", "")),
        )
        print(json.dumps(value, sort_keys=True))
        return 0
    except Exception as exc:
        reason = (str(exc) if isinstance(exc, ValidationBlocked)
                  and re.fullmatch(r"[a-z][a-z0-9_]{1,100}", str(exc))
                  else "independent_validator_unverified")
        print(json.dumps({"result": "ISSUE8_INDEPENDENT_VALIDATOR_BLOCKED",
                          "reason_code": reason, "ready_for_pr": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
