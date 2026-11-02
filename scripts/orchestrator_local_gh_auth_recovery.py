#!/usr/bin/env python3
"""Recover the owner's GitHub CLI login on the Desktop in a governed session.

The Gateway invokes this fixed DEV action. GitHub's one-time code stays in the
Desktop clipboard and never enters Gateway output or an artifact.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys

sys.dont_write_bytecode = True

HOST = "DESKTOP-PDQK954"
WINDOWS_USER = "windows"
OWNER = "ericson-j-santos"
ORIGIN = "https://github.com/ericson-j-santos/desktop-pc24x7-runtime.git"
CONFIRM = "RECOVER-ORCHESTRATOR-DEV-GITHUB-AUTH"
SHA = re.compile(r"^[0-9a-f]{40}$")


def emit(ok: bool, state: str) -> int:
    print(json.dumps({
        "ok": ok, "state": state, "host": HOST, "environment": "DEV",
        "owner_validated": ok, "credential_material_emitted": False,
    }, sort_keys=True))
    return 0 if ok else 2


def check_source(expected_sha: str) -> bool:
    if not SHA.fullmatch(expected_sha):
        return False
    root = Path(__file__).resolve().parents[1]
    checks = (
        (["git", "rev-parse", "HEAD"], expected_sha),
        (["git", "remote", "get-url", "origin"], ORIGIN),
        (["git", "status", "--porcelain=v1", "--untracked-files=all"], ""),
        (["git", "ls-files", "--error-unmatch", "scripts/orchestrator_local_gh_auth_recovery.py"],
         "scripts/orchestrator_local_gh_auth_recovery.py"),
    )
    for command, expected in checks:
        try:
            result = subprocess.run(
                command, cwd=root, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if result.returncode != 0 or result.stdout.strip() != expected:
            return False
    return True


def safe_context() -> bool:
    if os.name != "nt" or socket.gethostname().casefold() != HOST.casefold():
        return False
    if getpass.getuser().casefold() != WINDOWS_USER:
        return False
    profile = os.environ.get("USERPROFILE")
    appdata = os.environ.get("APPDATA")
    if not profile or not appdata:
        return False
    try:
        Path(appdata).resolve().relative_to(Path(profile).resolve())
    except (OSError, ValueError):
        return False
    session_id = wintypes.DWORD()
    if not ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
        return False
    if session_id.value == 0:
        return False
    return True


def gh_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in ("GH_TOKEN", "GITHUB_TOKEN", "GH_CONFIG_DIR", "XDG_CONFIG_HOME"):
        env.pop(name, None)
    return env


def owner_validated(gh: str, env: dict[str, str]) -> bool:
    try:
        result = subprocess.run(
            [gh, "api", "user", "--jq", ".login"], env=env,
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip().casefold() == OWNER


def recover(expected_sha: str, confirm: str) -> int:
    if confirm != CONFIRM or not safe_context() or not check_source(expected_sha):
        return emit(False, "governed_context_invalid")
    gh = shutil.which("gh")
    if not gh:
        return emit(False, "github_cli_unavailable")
    env = gh_environment()
    if owner_validated(gh, env):
        return emit(True, "owner_already_validated")
    try:
        result = subprocess.run(
            [gh, "auth", "login", "--hostname", "github.com", "--web",
             "--clipboard", "--git-protocol", "https", "--scopes", "repo"],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=480, check=False,
        )
    except subprocess.TimeoutExpired:
        return emit(False, "browser_authorization_timeout")
    except OSError:
        return emit(False, "github_login_start_failed")
    if result.returncode != 0:
        return emit(False, "browser_authorization_incomplete")
    if not owner_validated(gh, env):
        return emit(False, "owner_validation_failed")
    return emit(True, "github_owner_validated")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    return recover(args.expected_sha, args.confirm)


if __name__ == "__main__":
    raise SystemExit(main())
