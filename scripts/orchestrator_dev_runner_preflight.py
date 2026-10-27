#!/usr/bin/env python3
"""Plano somente leitura de um runner exclusivo do orchestrator DEV."""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import json
import os
import re
import stat
import subprocess
from http.client import HTTPConnection, HTTPException
from pathlib import Path
from typing import Any

import bootstrap_dedicated_runtime_runner as bootstrap
import pc24x7_host_policy as host_policy

SOURCE_REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
SOURCE_PATHS = (
    "scripts/orchestrator_dev_runner_preflight.py",
    "scripts/bootstrap_dedicated_runtime_runner.py",
    "scripts/desktop_control_plane_watchdog.py",
    "scripts/pc24x7_host_policy.py",
)
PROFILE = host_policy.ORCHESTRATOR_DEV_RUNNER_PROFILE
REQUIRED_LABELS = host_policy.ORCHESTRATOR_DEV_RUNNER_REQUIRED_LABELS
MAX_RESPONSE_BYTES = 262144
MAX_METADATA_BYTES = 65536
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CORRELATION_RE = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")


def blocked(state: str) -> bootstrap.BootstrapError:
    return bootstrap.BootstrapError(state, state)


def require_source(expected_sha: str) -> None:
    if not SHA_RE.fullmatch(expected_sha):
        raise blocked("source_sha_invalid")
    root = Path(__file__).resolve().parents[1]
    imported = (
        (bootstrap, SOURCE_PATHS[1]),
        (bootstrap.watchdog, SOURCE_PATHS[2]),
        (host_policy, SOURCE_PATHS[3]),
    )
    if any(Path(module.__file__).resolve() != root / path for module, path in imported):
        raise blocked("source_import_path_mismatch")
    observed: list[str] = []
    commands = [
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=no"],
        ["git", "-C", str(root), "remote", "get-url", "origin"],
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", *SOURCE_PATHS],
    ]
    env = bootstrap.gh_env()
    env["GIT_OPTIONAL_LOCKS"] = "0"
    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise blocked("source_readback_unavailable") from None
        if result.returncode != 0:
            state = "source_files_untracked" if "ls-files" in command else "source_readback_failed"
            raise blocked(state)
        observed.append(result.stdout.strip())
    if observed[0] != expected_sha:
        raise blocked("source_sha_mismatch")
    if observed[1]:
        raise blocked("source_tracked_tree_dirty")
    allowed_origins = {
        f"https://github.com/{SOURCE_REPOSITORY}",
        f"https://github.com/{SOURCE_REPOSITORY}.git",
        f"git@github.com:{SOURCE_REPOSITORY}.git",
    }
    if observed[2] not in allowed_origins:
        raise blocked("source_repository_mismatch")
    if sorted(observed[3].splitlines()) != sorted(SOURCE_PATHS):
        raise blocked("source_files_untracked")


def checked_path(
    path: Path, *, directory: bool, allow_missing_tail: bool = False,
) -> bool:
    """Inspect all existing ancestors; never create a missing planned tail."""
    if not path.is_absolute() or ".." in path.parts:
        raise blocked("runner_path_invalid")
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            if allow_missing_tail:
                return False
            raise blocked("runner_path_missing") from None
        except OSError:
            raise blocked("runner_path_unavailable") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise blocked("runner_path_link_rejected")
        needs_directory = component != path or directory
        valid_type = stat.S_ISDIR(info.st_mode) if needs_directory else stat.S_ISREG(info.st_mode)
        if not valid_type:
            raise blocked("runner_path_type_invalid")
    return True


def runner_home() -> Path:
    local = os.environ.get("LOCALAPPDATA", "")
    if not local or not Path(local).is_absolute():
        raise blocked("localappdata_invalid")
    base = Path(local)
    if base.drive.startswith("\\\\"):
        raise blocked("localappdata_network_path_rejected")
    checked_path(base, directory=True)
    home = base / PROFILE["directory"] / "GitHubRunner"
    checked_path(home, directory=True, allow_missing_tail=True)
    return home


def read_loopback(path: str) -> dict[str, Any]:
    if path not in {"/readyz", "/v1/workers"}:
        raise blocked("orchestrator_path_rejected")
    connection = HTTPConnection("127.0.0.1", 8787, timeout=5)
    try:
        connection.request(
            "GET", path,
            headers={"Accept": "application/json", "Cache-Control": "no-store"},
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if response.status != 200:
            raise blocked("orchestrator_http_not_ready")
        if len(body) > MAX_RESPONSE_BYTES:
            raise blocked("orchestrator_response_too_large")
        payload = json.loads(body.decode("utf-8"))
    except bootstrap.BootstrapError:
        raise
    except (OSError, HTTPException, UnicodeDecodeError, ValueError):
        raise blocked("orchestrator_readback_unavailable") from None
    finally:
        connection.close()
    if not isinstance(payload, dict):
        raise blocked("orchestrator_response_invalid")
    return payload


def require_orchestrator() -> None:
    if read_loopback("/readyz").get("ready") is not True:
        raise blocked("orchestrator_not_ready")
    workers = read_loopback("/v1/workers").get("workers")
    if not isinstance(workers, list):
        raise blocked("orchestrator_worker_registry_invalid")
    matching = [
        worker for worker in workers
        if isinstance(worker, dict)
        and str(worker.get("device_name") or "").casefold()
        == PROFILE["host"].casefold()
    ]
    if len(matching) != 1:
        raise blocked("orchestrator_desktop_worker_not_unique")
    worker = matching[0]
    if (
        worker.get("fresh") is not True
        or worker.get("controller_online") is not True
        or worker.get("auth_valid") is not True
        or str(worker.get("profile") or "").upper() != "NORMAL"
    ):
        raise blocked("orchestrator_desktop_worker_not_ready")


def registry_snapshot(*, local_auth_only: bool = False) -> dict[str, Any] | None:
    token = None if local_auth_only else os.environ.get("GH_TOKEN", "").strip() or None
    payload = bootstrap.api_json(
        f"/repos/{PROFILE['repository']}/actions/runners?per_page=100",
        method="GET",
        token=token,
    )
    runners = payload.get("runners")
    total = payload.get("total_count")
    if (
        not isinstance(runners, list)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total != len(runners)
    ):
        raise blocked("runner_registry_incomplete")
    matches = [
        item for item in runners
        if isinstance(item, dict)
        and str(item.get("name") or "").casefold()
        == PROFILE["runner_name"].casefold()
    ]
    if len(matches) > 1:
        raise blocked("runner_registry_ambiguous")
    return matches[0] if matches else None


def require_local_binding(home: Path, remote: dict[str, Any] | None) -> None:
    home_present = checked_path(home, directory=True, allow_missing_tail=True)
    metadata = home / ".runner"
    metadata_present = checked_path(metadata, directory=False, allow_missing_tail=True)
    if not metadata_present:
        if remote is not None:
            raise blocked("remote_local_divergence")
        try:
            nonempty = home_present and any(home.iterdir())
        except OSError:
            raise blocked("runner_path_unavailable") from None
        if nonempty:
            raise blocked("runner_home_not_empty")
        return
    if remote is None:
        raise blocked("local_remote_divergence")
    try:
        with metadata.open("rb") as stream:
            raw = stream.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise blocked("runner_metadata_too_large")
        data = json.loads(raw.decode("utf-8-sig"))
    except bootstrap.BootstrapError:
        raise
    except (OSError, UnicodeDecodeError, ValueError):
        raise blocked("runner_metadata_invalid") from None
    if not isinstance(data, dict):
        raise blocked("runner_metadata_invalid")
    expected_url = f"https://github.com/{PROFILE['repository']}"
    urls = [data[key] for key in ("repoUrl", "gitHubUrl") if key in data]
    if not urls or any(
        not isinstance(url, str) or url.rstrip("/") != expected_url
        for url in urls
    ):
        raise blocked("runner_repository_mismatch")
    names = [data[key] for key in ("agentName", "runnerName") if key in data]
    if not names or any(
        not isinstance(name, str) or name != PROFILE["runner_name"] for name in names
    ):
        raise blocked("runner_name_mismatch")
    local_id, remote_id = data.get("agentId"), remote.get("id")
    if (
        type(local_id) is not int or local_id <= 0
        or type(remote_id) is not int or remote_id <= 0
        or local_id != remote_id
    ):
        raise blocked("runner_id_mismatch")
    labels = remote.get("labels")
    names = {
        str(item.get("name") or "").casefold()
        for item in labels if isinstance(item, dict)
    } if isinstance(labels, list) else set()
    if not {label.casefold() for label in REQUIRED_LABELS}.issubset(names):
        raise blocked("runner_labels_mismatch")


def preflight(
    *, expected_sha: str, correlation_id: str, local_auth_only: bool = False,
) -> dict[str, Any]:
    if not CORRELATION_RE.fullmatch(correlation_id):
        raise blocked("correlation_id_invalid")
    require_source(expected_sha)
    if bootstrap.validate_host().casefold() != PROFILE["host"].casefold():
        raise blocked("orchestrator_runner_host_not_authorized")
    home = runner_home()
    remote = registry_snapshot(local_auth_only=True) if local_auth_only else registry_snapshot()
    require_local_binding(home, remote)
    require_orchestrator()
    return {
        "ok": True,
        "state": "READ_ONLY_PLAN_RECORDED_EXECUTION_PENDING",
        "mode": "preflight_only",
        "profile": dict(PROFILE),
        "source_sha": expected_sha,
        "correlation_id": correlation_id,
        "runner_home": str(home),
        "required_labels": sorted(REQUIRED_LABELS),
        "registration_required": remote is None,
        "observed_runner_id": remote.get("id") if remote else None,
        "read_only": True,
        "execution_authorized": False,
        "registration_performed": False,
        "registration_token_requested": False,
        "runner_started": False,
        "watchdog_changed": False,
        "runner_version_preflight_proven": False,
        "physical_pickup_proven": False,
        "continuous_operation_proven": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--correlation-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = preflight(
            expected_sha=args.expected_sha,
            correlation_id=args.correlation_id,
        )
    except bootstrap.BootstrapError as exc:
        result = {
            "ok": False,
            "state": exc.state,
            "read_only": True,
            "execution_authorized": False,
            "registration_performed": False,
            "registration_token_requested": False,
            "runner_version_preflight_proven": False,
            "physical_pickup_proven": False,
        }
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
