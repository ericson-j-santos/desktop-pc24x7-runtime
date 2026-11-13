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
    targets = {}
    for key, segments in FILES.items():
        target = root.joinpath(*segments)
        if segments[0] == "releases":
            target = root / "releases" / installed_sha / "scripts" / segments[-1]
        targets[key] = target
        results[key] = hashlib.sha256(_read_stable(target, root, 2 * 1024 * 1024)).hexdigest()
    if _read_stable(metadata_path, root, 65536) != metadata_raw:
        raise InventoryBlocked("metadata_changed_during_inventory")
    # Verify the entire observed generation once more, not just each file
    # independently, so an earlier file cannot change while later files
    # are being hashed and yield a mixed-version inventory receipt.
    for key, target in targets.items():
        observed = hashlib.sha256(_read_stable(target, root, 2 * 1024 * 1024)).hexdigest()
        if observed != results[key]:
            raise InventoryBlocked("file_changed_during_inventory")
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



def runtime_root_from_task(task: dict[str, Any]) -> Path:
    """Resolve the *registered* watchdog launcher, never runner LOCALAPPDATA.

    The GitHub runner may execute as LocalSystem while the watchdog runs in
    a different Windows user profile. Its task action is the authoritative
    local read-only locator, and must still match the fixed runtime suffix.
    """
    if not isinstance(task, dict):
        raise InventoryBlocked("task_readback_invalid")
    launcher_value = task.get("launcher")
    workdir_value = task.get("working_directory")
    if not isinstance(launcher_value, str) or not isinstance(workdir_value, str):
        raise InventoryBlocked("task_readback_invalid")
    launcher = Path(launcher_value)
    root = launcher.parent
    if (launcher.name.casefold() != "run.py"
            or root.name.casefold() != "controlplanewatchdog"
            or root.parent.name.casefold() != "desktoppc24x7"
            or str(root).casefold() != str(Path(workdir_value)).casefold()):
        raise InventoryBlocked("task_launcher_path_invalid")
    _no_links(launcher)
    if not launcher.is_file() or not root.is_dir():
        raise InventoryBlocked("task_launcher_missing")
    return root



def upgrade_profile_root_aligned(task_root: Path, runner_localappdata: str | None) -> bool:
    """Report whether the existing upgrader would open the same installation.

    The existing upgrader derives default_runtime_root() from LOCALAPPDATA.
    Never treat the inventory hashes as an upgrade preflight when a service
    runner (e.g. LocalSystem) points to a different profile than task S4U.
    This is a read-only observation, never an upgrade authorization.
    """
    if not isinstance(runner_localappdata, str) or not runner_localappdata.strip():
        return False
    profile = Path(runner_localappdata)
    if not profile.is_absolute():
        return False
    expected_root = profile / "DesktopPC24x7" / "ControlPlaneWatchdog"
    try:
        _no_links(task_root)
        _no_links(expected_root)
        return expected_root.resolve(strict=True) == task_root.resolve(strict=True)
    except (InventoryBlocked, OSError, ValueError):
        return False


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
        # Reuse the existing fixed, read-only Task Scheduler readback. Never
        # guess the S4U installation from the LocalSystem runner profile.
        try:
            from lenovo_control_plane_pickup import task_runtime_readback
            task = task_runtime_readback()
        except Exception as exc:
            raise InventoryBlocked("task_readback_unavailable") from exc
        root = runtime_root_from_task(task)
        result = collect(root, host=socket.gethostname().upper(), runner=os.environ["RUNNER_NAME"])
        result["upgrade_profile_root_aligned"] = upgrade_profile_root_aligned(
            root, os.environ.get("LOCALAPPDATA"))
    except (InventoryBlocked, OSError, ValueError, TypeError) as exc:
        print(json.dumps({"result": "BLOCKED", "reason": _safe_reason(exc),
                          "mutation_performed": False, "upgrade_authorized": False},
                         sort_keys=True))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
