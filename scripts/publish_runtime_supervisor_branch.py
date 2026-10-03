#!/usr/bin/env python3
"""Publica somente a branch governada do incremento runtime-supervisor."""
from __future__ import annotations

import subprocess
import sys
import json

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
    listed = subprocess.run(
        ["gh", "pr", "list", "--repo", "ericson-j-santos/desktop-pc24x7-runtime",
         "--head", EXPECTED_BRANCH, "--state", "open", "--json", "url"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if listed.returncode != 0:
        raise RuntimeError(f"consulta de PR falhou: exit={listed.returncode}")
    existing = json.loads(listed.stdout or "[]")
    if existing:
        url = existing[0]["url"]
    else:
        created = subprocess.run(
            [
                "gh", "pr", "create", "--repo", "ericson-j-santos/desktop-pc24x7-runtime",
                "--base", "main", "--head", EXPECTED_BRANCH,
                "--title", "feat: add bounded PC24x7 runtime supervisor",
                "--body", (
                    "Implementa supervisor Pareto com circuit breaker, canario fisico a cada "
                    "cinco minutos e evidencias fail-closed para runner, orquestrador e Worker Pool."
                ),
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        )
        if created.returncode != 0:
            raise RuntimeError(f"criacao de PR falhou: exit={created.returncode}")
        url = created.stdout.strip()
    print(f"PUBLISH_OK branch={EXPECTED_BRANCH} head={head} pr={url}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2)
