#!/usr/bin/env python3
"""Inventário somente leitura de candidatos Git. Entrada exclusiva via Gateway Risk 1.

A execução NÃO autentica nem executa git.exe. Um arquivo presente não autoriza
usá-lo, instalar programas ou prosseguir sem Session Launcher/Gateway.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
from pathlib import Path
from typing import Mapping

EXPECTED_HOST = "DESKTOP-RP23OGS"
EXPECTED_RUNNER = "DESKTOP-RP23OGS-runtime"
CONTRACT = "lenovo-git-discovery-readonly-v2"
CANDIDATES = (
    ("system", "ProgramFiles", ("Git", "cmd", "git.exe")),
    ("system64", "ProgramW6432", ("Git", "cmd", "git.exe")),
    ("system32", "ProgramFiles(x86)", ("Git", "cmd", "git.exe")),
    ("user", "LOCALAPPDATA", ("Programs", "Git", "cmd", "git.exe")),
    ("mingit", "ProgramData", ("ReqSys", "MinGit", "cmd", "git.exe")),
    ("portable", "LOCALAPPDATA", ("Programs", "Git", "bin", "git.exe")),
    ("vscode", "LOCALAPPDATA",
     ("Programs", "Microsoft VS Code", "resources", "app", "extensions", "git", "bin", "git.exe")),
)


class DiscoveryBlocked(RuntimeError):
    pass


def _link_or_junction(path: Path) -> bool:
    """Não atravessar redirecionamentos (Windows junction ou symlink)."""
    for entry in (path, *path.parents):
        if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
            return True
    return False


def _state(path: Path | None) -> str:
    if path is None:
        return "root_unavailable"
    try:
        if _link_or_junction(path):
            return "link_rejected"
        return "file_present_unverified" if path.is_file() else "missing"
    except OSError:
        return "unreadable"


def collect(env: Mapping[str, str], *, host: str, runner: str) -> dict:
    """Sem escrita e sem executar candidatos; saída sem caminhos absolutos."""
    if host != EXPECTED_HOST or runner != EXPECTED_RUNNER or env.get("DEPLOYMENT_ENV") != "DEV":
        raise DiscoveryBlocked("LENOVO_GIT_DISCOVERY_HOST_REJECTED")
    results: list[dict[str, str]] = []
    for label, root_key, suffix in CANDIDATES:
        root = env.get(root_key, "")
        base = Path(root) if root and Path(root).is_absolute() else None
        results.append({"candidate": label, "state": _state(base.joinpath(*suffix) if base else None)})
    local = env.get("LOCALAPPDATA", "")
    base = Path(local) if local and Path(local).is_absolute() else None
    desktop = base / "GitHubDesktop" if base else None
    if desktop and not _link_or_junction(desktop) and desktop.is_dir():
        try:
            # A lista é limitada e o resultado não revela perfis nem caminhos.
            versions = sorted(x for x in desktop.glob("app-*")
                              if x.is_dir() and not _link_or_junction(x))[:12]
            for index, app in enumerate(versions):
                for kind, suffix in (
                    ("cmd", ("resources", "app", "git", "cmd", "git.exe")),
                    ("mingw64", ("resources", "app", "git", "mingw64", "bin", "git.exe")),
                ):
                    results.append({"candidate": f"desktop_{index}_{kind}",
                                    "state": _state(app.joinpath(*suffix))})
        except OSError:
            results.append({"candidate": "github_desktop", "state": "unreadable"})
    return {
        "contract": CONTRACT,
        "result": "LENOVO_GIT_CANDIDATES_ONLY",
        "host": EXPECTED_HOST,
        "runner_name": EXPECTED_RUNNER,
        "git_verified": False,
        "execution_authorized": False,
        "mutation_performed": False,
        "path_lookup_present": bool(shutil.which("git")),
        "candidates": results,
    }


def main() -> int:
    if os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise DiscoveryBlocked("LENOVO_GIT_DISCOVERY_RUNTIME_REJECTED")
    report = collect(os.environ, host=socket.gethostname().upper(),
                     runner=os.environ.get("RUNNER_NAME", ""))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
