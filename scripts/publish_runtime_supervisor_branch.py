#!/usr/bin/env python3
"""Publica somente a branch governada do incremento runtime-supervisor."""
from __future__ import annotations

import subprocess
import sys

EXPECTED_BRANCH = "feat/runtime-supervisor-canary"
EXPECTED_REMOTE = "https://github.com/ericson-j-santos/desktop-pc24x7-runtime.git"


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=False,
    )


def checked(*args: str) -> str:
    result = git(*args)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} falhou: exit={result.returncode}")
    return result.stdout.strip()


def main() -> int:
    if checked("status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError("worktree deve estar limpo")
    if checked("branch", "--show-current") != EXPECTED_BRANCH:
        raise RuntimeError("branch nao autorizada")
    remote = checked("remote", "get-url", "origin").removesuffix("/")
    if remote.removesuffix(".git") != EXPECTED_REMOTE.removesuffix(".git"):
        raise RuntimeError("remote nao autorizado")
    head = checked("rev-parse", "HEAD")
    result = git("push", "--set-upstream", "origin", f"HEAD:{EXPECTED_BRANCH}")
    if result.returncode != 0:
        raise RuntimeError(f"push falhou: exit={result.returncode}")
    print(f"PUBLISH_OK branch={EXPECTED_BRANCH} head={head}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
