#!/usr/bin/env python3
"""Inventário somente leitura da instalação Lenovo DEV, sem tocar em runner/watchdog.

Saída contém apenas SHA da versão, hashes dos três arquivos e sinal de
consistência. Isto NÃO prova readiness, não autentica o recibo externo,
não executa upgrade e não autoriza dispatch.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
from pathlib import Path
from typing import Any

HOST = "DESKTOP-RP23OGS"
RUNNER = "DESKTOP-RP23OGS-runtime"
REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
ACTOR = "ericson-j-santos"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
FILES = {
    "expected_watchdog_sha256": ("releases", "scripts", "desktop_control_plane_watchdog.py"),
    "expected_uac_sha256": ("releases", "scripts", "desktop_control_plane_watchdog_uac_launcher.py"),
    "expected_launcher_sha256": ("run.py",),
}


class InventoryBlocked(RuntimeError):
    pass


def _safe_reason(error: BaseException) -> str:
    reason = str(error)
    return reason if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", reason) else "inventory_unavailable"


def _no_links(path: Path) -> None:
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise InventoryBlocked("reparse_path_blocked")


def _read_stable(path: Path, root: Path, limit: int) -> bytes:
    _no_links(root)
    _no_links(path)
    try:
        if not path.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
            raise InventoryBlocked("path_outside_runtime")
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise InventoryBlocked("file_type_or_size_invalid")
        first = path.read_bytes()
        mid = path.stat()
        second = path.read_bytes()
        after = path.stat()
    except (OSError, ValueError) as exc:
        raise InventoryBlocked("file_read_unavailable") from exc
    if (len(first) != before.st_size or first != second
            or before.st_size != mid.st_size or mid.st_size != after.st_size
            or before.st_mtime_ns != mid.st_mtime_ns
            or mid.st_mtime_ns != after.st_mtime_ns):
        raise InventoryBlocked("file_changed_during_readback")
    return second


def collect(root: Path, *, host: str, runner: str) -> dict[str, Any]:
    """Only fixed filenames. Run under a separately authenticated Gateway session."""
    if host != HOST:
        raise InventoryBlocked("physical_host_mismatch")
    if runner != RUNNER:
        raise InventoryBlocked("runner_identity_mismatch")
    _no_links(root)
    if not root.is_dir():
        raise InventoryBlocked("runtime_root_missing")
    metadata_path = root / "metadata.json"
    metadata_raw = _read_stable(metadata_path, root, 65536)
    try:
        metadata = json.loads(metadata_raw)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise InventoryBlocked("metadata_invalid") from exc
    if not isinstance(metadata, dict):
        raise InventoryBlocked("metadata_invalid")
    installed_sha = metadata.get("source_sha")
    if not isinstance(installed_sha, str) or not SHA40.fullmatch(installed_sha):
        raise InventoryBlocked("installed_source_sha_invalid")
    if metadata.get("host") != HOST:
        raise InventoryBlocked("metadata_host_mismatch")
    release = root / "releases" / installed_sha
    if (str(metadata.get("runtime_root") or "").casefold() != str(root).casefold()
            or str(metadata.get("release_root") or "").casefold() != str(release).casefold()):
        raise InventoryBlocked("metadata_root_mismatch")
    results = {}
    for key, segments in FILES.items():
        target = root.joinpath(*segments)
        if segments[0] == "releases":
            target = root / "releases" / installed_sha / "scripts" / segments[-1]
        results[key] = hashlib.sha256(_read_stable(target, root, 2 * 1024 * 1024)).hexdigest()
    if _read_stable(metadata_path, root, 65536) != metadata_raw:
        raise InventoryBlocked("metadata_changed_during_inventory")
    return {
        "contract": "lenovo-installed-inventory-readonly-v1",
        "result": "INSTALLED_INVENTORY_READ_ONLY",
        "host": HOST,
        "runner_name": RUNNER,
        "expected_installed_sha": installed_sha,
        "metadata_sha256": hashlib.sha256(metadata_raw).hexdigest(),
        **results,
        "double_read_verified": True,
        "mutation_performed": False,
        "runner_health_proven": False,
        "github_pickup_proven": False,
        "upgrade_authorized": False,
    }


def main() -> int:
    try:
        expected = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_ACTOR": ACTOR,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_RUN_ATTEMPT": "1",
            "RUNNER_NAME": RUNNER,
        }
        if any(os.environ.get(key) != value for key, value in expected.items()):
            raise InventoryBlocked("github_execution_context_invalid")
        if os.name != "nt" or socket.gethostname().upper() != HOST:
            raise InventoryBlocked("physical_host_mismatch")
        if not isinstance(os.environ.get("GITHUB_SHA"), str) or not SHA40.fullmatch(os.environ["GITHUB_SHA"]):
            raise InventoryBlocked("github_source_sha_invalid")
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise InventoryBlocked("localappdata_missing")
        root = Path(local) / "DesktopPC24x7" / "ControlPlaneWatchdog"
        result = collect(root, host=socket.gethostname().upper(), runner=os.environ["RUNNER_NAME"])
    except (InventoryBlocked, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"result": "BLOCKED", "reason": _safe_reason(exc),
                          "mutation_performed": False, "upgrade_authorized": False},
                         sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
