#!/usr/bin/env python3
"""Materialize only the authorized ReqSys DEV source within a fixed new namespace."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

REMOTE = "https://github.com/ericson-j-santos/reqsys-v2-enterprise-real.git"
REF = "fix/self-hosted-dev-restore-20261003"
ROOT = Path(r"C:\dev\chatgpt-workers")
SOURCE_PREFIX = "rs2-"


class SourceError(RuntimeError):
    pass


def fail(code: str) -> None:
    raise SourceError(code)


def no_reparse(path: Path) -> None:
    for candidate in (path, *path.parents):
        try:
            information = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(information.st_mode) or (
            getattr(information, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            fail("SOURCE_PATH_REPARSE_BLOCKED")


def git_failure_code(stderr: str) -> str:
    # Only fixed classifications leave this function, never Git stderr or credentials.
    lowered = stderr.casefold()
    if "filename too long" in lowered or "file name too long" in lowered:
        return "SOURCE_GIT_FILENAME_TOO_LONG"
    if "invalid path" in lowered or "invalid argument" in lowered:
        return "SOURCE_GIT_INVALID_PATH"
    if "permission denied" in lowered or "access is denied" in lowered:
        return "SOURCE_GIT_PERMISSION_DENIED"
    if "could not resolve host" in lowered or "failed to connect" in lowered:
        return "SOURCE_GIT_NETWORK_UNAVAILABLE"
    if "authentication failed" in lowered or "could not read username" in lowered:
        return "SOURCE_GIT_AUTH_UNAVAILABLE"
    return "SOURCE_GIT_FAILED"


def git(args: list[str], cwd: Path) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    try:
        completed = subprocess.run(["git", "-c", "core.longpaths=true", *args],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=180, check=False,
            shell=False)
    except (OSError, subprocess.TimeoutExpired):
        fail("SOURCE_GIT_UNAVAILABLE")
    if completed.returncode != 0:
        fail(git_failure_code(completed.stderr or ""))
    return completed.stdout.strip()


def materialize(sha: str) -> Path:
    if socket.gethostname().casefold() != "desktop-pdqk954":
        fail("FIXED_HOST_MISMATCH")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        fail("SOURCE_SHA_INVALID")
    no_reparse(ROOT)
    ROOT.mkdir(parents=True, exist_ok=True)
    target = ROOT / (SOURCE_PREFIX + sha)
    no_reparse(target)
    if target.exists():
        if not (target / ".git").is_dir():
            fail("SOURCE_TARGET_UNTRUSTED")
        no_reparse(target / ".git")
    else:
        # Repository-local config survives subsequent SessionLauncher/worktree calls.
        git(["clone", "--config", "core.longpaths=true", "--depth", "1",
             "--single-branch", "--branch", REF, "--no-checkout", REMOTE,
             str(target)], ROOT)
        no_reparse(target)
        no_reparse(target / ".git")
        if not (target / ".git").is_dir():
            fail("SOURCE_CLONE_NOT_A_REPOSITORY")
        observed = git(["rev-parse", "HEAD"], target)
        if observed != sha:
            fail("SOURCE_BRANCH_ADVANCED")
        git(["checkout", "--detach", sha], target)
    # Existing partial or edited clones are refused. Never reset/delete user trees.
    if git(["remote", "get-url", "origin"], target) != REMOTE:
        fail("SOURCE_ORIGIN_MISMATCH")
    if git(["config", "--local", "--get", "core.longpaths"], target).casefold() != "true":
        fail("SOURCE_LOCAL_LONGPATHS_REQUIRED")
    if git(["rev-parse", "HEAD"], target) != sha:
        fail("SOURCE_HEAD_MISMATCH")
    if git(["status", "--porcelain", "--untracked-files=all"], target):
        fail("SOURCE_TREE_NOT_CLEAN")
    if git(["rev-parse", "--abbrev-ref", "HEAD"], target) != "HEAD":
        fail("SOURCE_MUST_BE_DETACHED")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-sha", required=True)
    args = parser.parse_args()
    try:
        source = materialize(args.expected_sha)
        print(json.dumps({"result": "REQSYS_DEV_SOURCE_READY", "source_root": str(source),
                          "source_sha": args.expected_sha, "source_ref": REF,
                          "local_longpaths": True}, sort_keys=True))
        return 0
    except SourceError as exc:
        print(json.dumps({"result": "REQSYS_DEV_SOURCE_BLOCKED", "code": str(exc)}))
        return 1
    except Exception as exc:
        print(json.dumps({"result": "REQSYS_DEV_SOURCE_BLOCKED", "code": "SOURCE_UNAVAILABLE",
                          "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
