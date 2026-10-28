#!/usr/bin/env python3
"""Dispatch one fixed PR113 preflight after local auth repair and current CI."""
from __future__ import annotations
import argparse
import json
import time
import urllib.request
import sys
sys.dont_write_bytecode = True
import bootstrap_dedicated_runtime_runner as bootstrap
import orchestrator_dev_runner_preflight as preflight

REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
BRANCH = "feat/orchestrator-dev-runner-preflight-20261027"
MAIN = "18fb89dc2c788d0c0e268908971c24215c4872f3"
RULES = "d6af41001bf641727a35a990e7c93b4c757538cb"
PARENT = "7e51a578a59afa7ee955139c2f6bc3df72509ef6"
WORKFLOW = "dedicated-runtime-runner-e2e.yml"
PREFIX = "/repos/" + REPOSITORY


def require(condition: bool, state: str) -> None:
    if not condition:
        raise bootstrap.BootstrapError(state, state)


def latest_ci(payload: dict, sha: str, event: str) -> dict | None:
    runs = payload.get("workflow_runs")
    require(isinstance(runs, list) and type(payload.get("total_count")) is int
            and payload["total_count"] == len(runs), "dispatch_ci_listing_incomplete")
    matches = [run for run in runs if run.get("head_sha") == sha
               and run.get("event") == event and run.get("head_branch") == BRANCH
               and run.get("repository", {}).get("full_name") == REPOSITORY]
    for run in matches:
        require(type(run.get("id")) is int and run["id"] > 0
                and type(run.get("run_attempt")) is int and run["run_attempt"] > 0
                and isinstance(run.get("created_at"), str), "dispatch_ci_metadata_invalid")
    return max(matches, key=lambda run: (run["created_at"], run["id"])) if matches else None


def require_ci_jobs(payload: dict, run_id: int) -> None:
    jobs = payload.get("jobs")
    require(isinstance(jobs, list) and payload.get("total_count") == len(jobs),
            "dispatch_ci_jobs_incomplete")
    for name, label in (
        ("Python compile and tests", "windows-latest"),
        ("Portable Linux compile and tests", "ubuntu-latest"),
    ):
        matches = [job for job in jobs if job.get("name") == name]
        require(len(matches) == 1, "dispatch_ci_job_missing")
        job = matches[0]
        require(job.get("run_id") == run_id and job.get("status") == "completed"
                and job.get("conclusion") == "success" and label in job.get("labels", [])
                and job.get("started_at") and job.get("completed_at"),
                "dispatch_ci_job_not_success")
        for step in ("Compile", "Unit and negative-control tests"):
            require(any(item.get("name") == step and item.get("status") == "completed"
                        and item.get("conclusion") == "success" for item in job.get("steps", [])),
                    "dispatch_ci_step_missing")


def existing_runs(payload: dict, sha: str) -> list[dict]:
    runs = payload.get("workflow_runs")
    require(isinstance(runs, list) and payload.get("total_count") == len(runs),
            "dispatch_run_listing_incomplete")
    matches = [run for run in runs if run.get("head_sha") == sha
               and run.get("head_branch") == BRANCH and run.get("event") == "workflow_dispatch"]
    require(len(matches) <= 1, "dispatch_duplicate_runs_detected")
    if matches:
        run = matches[0]
        require(type(run.get("id")) is int and run["id"] > 0
                and run.get("run_attempt") == 1, "dispatch_existing_run_invalid")
    return matches


def dispatch(expected_sha: str, correlation_id: str) -> dict:
    require(bool(preflight.SHA_RE.fullmatch(expected_sha))
            and bool(preflight.CORRELATION_RE.fullmatch(correlation_id)), "dispatch_request_invalid")
    preflight.require_source(expected_sha)
    require(bootstrap.validate_host().casefold() == "desktop-pdqk954", "dispatch_host_mismatch")
    # Exercise the repaired bootstrap route before scheduling any physical proof.
    bootstrap.local_gh_api_json(
        "/repos/ericson-j-santos/reqsys-engineering-orchestrator/actions/runners?per_page=100"
    )
    preflight.require_orchestrator()
    token = bootstrap.local_git_owner_token()
    def read(path: str) -> dict:
        return bootstrap.api_json(path, token=token)
    def source_current() -> None:
        current = read(PREFIX + "/branches/" + BRANCH)
        main = read(PREFIX + "/branches/main")
        rules = read("/repos/ericson-j-santos/chatgpt-operational-rules/branches/main")
        commit = read(PREFIX + "/git/commits/" + expected_sha)
        pr = read(PREFIX + "/pulls/113")
        require(current.get("commit", {}).get("sha") == expected_sha
                and main.get("commit", {}).get("sha") == MAIN
                and rules.get("commit", {}).get("sha") == RULES
                and commit.get("parents", [{}])[0].get("sha") == PARENT
                and pr.get("state") == "open" and pr.get("draft") is True
                and pr.get("head", {}).get("sha") == expected_sha
                and pr.get("base", {}).get("sha") == MAIN,
                "dispatch_source_moved")
    source_current()
    ci_ids = {}
    deadline = time.monotonic() + 360
    while True:
        ready = True
        for event in ("push", "pull_request"):
            run = latest_ci(read(PREFIX + "/actions/workflows/ci.yml/runs?head_sha="
                                 + expected_sha + "&event=" + event + "&per_page=100"),
                            expected_sha, event)
            if run is None or run.get("status") != "completed":
                ready = False
                continue
            require(run.get("conclusion") == "success", "dispatch_latest_ci_failed")
            require_ci_jobs(read(PREFIX + "/actions/runs/" + str(run["id"]) + "/jobs?filter=latest&per_page=100"), run["id"])
            ci_ids[event] = run["id"]
        if ready:
            break
        require(time.monotonic() < deadline, "dispatch_ci_wait_expired")
        time.sleep(15)
    source_current()
    runs_path = (PREFIX + "/actions/workflows/" + WORKFLOW + "/runs?head_sha="
                 + expected_sha + "&event=workflow_dispatch&per_page=100")
    prior = existing_runs(read(runs_path), expected_sha)
    receipt = {"kind": "orchestrator-fixed-preflight-dispatch", "source_sha": expected_sha,
               "main_sha": MAIN, "rules_sha": RULES, "correlation_id": correlation_id,
               "ci_run_ids": ci_ids, "registration_performed": False,
               "credential_logged": False, "dispatch_count": 0}
    if prior:
        receipt.update(state="EXISTING_RUN_REUSED", run_id=prior[0]["id"], attempt=1)
        return receipt
    body = json.dumps({"ref": BRANCH, "inputs": {
        "diagnostic": "orchestrator-runner-preflight",
        "orchestrator_source_sha": expected_sha,
        "lenovo_control_plane_pickup": "false", "inventory_source_sha": "",
    }}).encode()
    request = urllib.request.Request(
        "https://api.github.com" + PREFIX + "/actions/workflows/" + WORKFLOW + "/dispatches",
        data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"},
    )
    # Never retry POST, including uncertain outcomes. Only read back afterwards.
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            require(response.status == 204, "dispatch_response_invalid")
    except Exception:
        receipt["state"] = "DISPATCH_OUTCOME_UNCONFIRMED"
    else:
        receipt["state"] = "DISPATCH_SENT"
        receipt["dispatch_count"] = 1
    for _ in range(12):
        found = existing_runs(read(runs_path), expected_sha)
        if found:
            receipt.update(state="DISPATCH_READBACK_OK", run_id=found[0]["id"], attempt=1)
            return receipt
        time.sleep(5)
    raise bootstrap.BootstrapError("dispatch_outcome_unconfirmed_no_retry", "dispatch_outcome_unconfirmed_no_retry")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args()
    try:
        result = dispatch(args.expected_sha, args.correlation_id)
    except bootstrap.BootstrapError as error:
        result = {"ok": False, "state": error.state, "registration_performed": False}
    except Exception:
        result = {"ok": False, "state": "dispatch_blocked", "registration_performed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("state") in ("DISPATCH_READBACK_OK", "EXISTING_RUN_REUSED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
