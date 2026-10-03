#!/usr/bin/env python3
"""Materialize only the authorized ReqSys DEV source within the worker namespace."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess

REMOTE = "https://github.com/ericson-j-santos/reqsys-v2-enterprise-real.git"
REF = "fix/self-hosted-dev-restore-20261003"
ROOT = Path(r"C:\dev\chatgpt-workers")

def git(args: list[str], cwd: Path) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    try:
        p = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True,
                           text=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("SOURCE_GIT_UNAVAILABLE") from None
    if p.returncode != 0:
        raise RuntimeError("SOURCE_GIT_FAILED") from None
    return p.stdout.strip()

def materialize(sha: str) -> Path:
    if socket.gethostname().casefold() != "desktop-pdqk954":
        raise RuntimeError("FIXED_HOST_MISMATCH")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("SOURCE_SHA_INVALID")
    ROOT.mkdir(parents=True, exist_ok=True)
    if ROOT.is_symlink():
        raise RuntimeError("SOURCE_ROOT_LINK_BLOCKED")
    target = ROOT / ("reqsys-selfhost-source-" + sha)
    if target.exists():
        if target.is_symlink() or not (target / ".git").is_dir():
            raise RuntimeError("SOURCE_TARGET_UNTRUSTED")
    else:
        git(["clone", "--depth", "1", "--single-branch", "--branch", REF,
             "--no-checkout", REMOTE, str(target)], ROOT)
        observed = git(["rev-parse", "HEAD"], target)
        if observed != sha:
            raise RuntimeError("SOURCE_BRANCH_ADVANCED")
        git(["checkout", "--detach", sha], target)
    if git(["remote", "get-url", "origin"], target) != REMOTE:
        raise RuntimeError("SOURCE_ORIGIN_MISMATCH")
    if git(["rev-parse", "HEAD"], target) != sha:
        raise RuntimeError("SOURCE_HEAD_MISMATCH")
    if git(["status", "--porcelain", "--untracked-files=all"], target):
        raise RuntimeError("SOURCE_TREE_NOT_CLEAN")
    if git(["rev-parse", "--abbrev-ref", "HEAD"], target) != "HEAD":
        raise RuntimeError("SOURCE_MUST_BE_DETACHED")
    return target

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--expected-sha", required=True)
    a = p.parse_args()
    # Detached check cannot use symbolic-ref's expected nonzero result as a Git failure.
    source = materialize(a.expected_sha)
    print(json.dumps({"result":"REQSYS_DEV_SOURCE_READY","source_root":str(source),
                      "source_sha":a.expected_sha,"source_ref":REF}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
