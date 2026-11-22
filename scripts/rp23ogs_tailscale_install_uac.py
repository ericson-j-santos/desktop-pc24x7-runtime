#!/usr/bin/env python3
"""PASS-001: fixed Tailscale Windows MSI UAC transaction (RP23OGS DEV only).

Run ONLY via session-bootstrapped Command Gateway. Risk3 --install/--rollback
require an exact, separately allowlisted owner_risk3_gateway action bound to
this script, its Git HEAD and a clean exclusive worktree. No generic shell,
login, Tailnet activation, Serve, Funnel, credentials, restart or production.
"""
from __future__ import annotations

import argparse
import ctypes
import getpass
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import socket
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

try:
    from scripts import rp23ogs_tailscale_admission as adm
    from scripts import rp23ogs_tailscale_windows_evidence as evidence
    from scripts import rp23ogs_tailscale_stage_official_msi as staging
except ModuleNotFoundError:
    import rp23ogs_tailscale_admission as adm
    import rp23ogs_tailscale_windows_evidence as evidence
    import rp23ogs_tailscale_stage_official_msi as staging

CONTRACT = "pass001-rp23ogs-tailscale-msi-uac-v1"
CONFIRM_INSTALL = "INSTALL-TAILSCALE-1.104.7-RP23OGS-DEV-UAC"
CONFIRM_ROLLBACK = "ROLLBACK-TAILSCALE-1.104.7-RP23OGS-DEV-UAC"
SOURCE_SHA = "676b5b32fdd1aeaee90d8e8f38e222635b216fbdfbf877bf01cb1d7cda330ec5"
EXIT_BLOCK = 20
RISK3_SCOPE = "repo://desktop-pc24x7-runtime/pass001-tailscale-msi-dev"
RISK3_IDS = {"install": "pass001.tailscale.msi.install.rp23ogs.dev",
             "rollback": "pass001.tailscale.msi.rollback.rp23ogs.dev"}
INSTALLER = Path(r"C:\Windows\System32\msiexec.exe")


class InstallBlocked(RuntimeError):
    pass


# Diagnostic only. A user-writable receipt is never authority for installing,
# declaring UAC approval, package integrity, or successful rollback.
UAC_RECEIPT_SCHEMA = "pass001-rp23ogs-uac-diagnostic-v1"
UAC_RECEIPT_NAME = "uac-attempt-diagnostic.json"
UAC_PHASES = frozenset({
    "launch_requested", "launch_rejected", "elevated_process_handle_received",
    "wait_started", "wait_timeout_process_may_continue", "wait_failed",
    "process_exited", "postcondition_verified", "postcondition_failed",
})


def uac_receipt_path() -> Path:
    return fixed_cache() / UAC_RECEIPT_NAME


def _receipt_payload(operation: str, attempt_id: str, phase: str,
                     *, detail: str = "") -> dict[str, object]:
    if operation not in {"install", "rollback"} or phase not in UAC_PHASES:
        raise InstallBlocked("UAC_DIAGNOSTIC_PHASE_INVALID")
    if len(attempt_id) != 32 or any(c not in "0123456789abcdef" for c in attempt_id):
        raise InstallBlocked("UAC_DIAGNOSTIC_ID_INVALID")
    # All detail strings originate from a closed, non-sensitive allowlist.
    if detail not in {"", "cancelled", "launch_error", "no_process_handle",
                      "wait_timeout", "wait_failed", "wait_unexpected",
                      "msi_nonzero", "reboot_required", "readback_missing",
                      "exit_code_unavailable", "exit_zero"}:
        raise InstallBlocked("UAC_DIAGNOSTIC_DETAIL_INVALID")
    return {"schema": UAC_RECEIPT_SCHEMA, "host": adm.HOST, "environment": "DEV",
            "operation": operation, "attempt_id": attempt_id, "phase": phase,
            "detail": detail, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "diagnostic_only": True, "uac_approved": "NOT_ATTESTED",
            "installation_comproved": False, "rollback_tested": False}


def write_uac_diagnostic(operation: str, attempt_id: str, phase: str,
                         *, detail: str = "") -> None:
    """Atomic local receipt, never used for admission or independent validation."""
    target = uac_receipt_path()
    no_reparse(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and (not target.is_file() or target.is_symlink()):
        raise InstallBlocked("UAC_DIAGNOSTIC_TARGET_INVALID")
    payload = _receipt_payload(operation, attempt_id, phase, detail=detail)
    tmp = target.parent / (".uac-receipt-" + uuid.uuid4().hex + ".tmp")
    no_reparse(tmp)
    try:
        with tmp.open("x", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        no_reparse(target)
        if target.exists() and (not target.is_file() or target.is_symlink()):
            raise InstallBlocked("UAC_DIAGNOSTIC_TARGET_INVALID")
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()


def read_uac_diagnostic() -> dict[str, object]:
    """Read only trusted shape, not trusted outcome. Cannot trigger an installer."""
    path = uac_receipt_path()
    no_reparse(path)
    if not path.exists():
        return {"schema": UAC_RECEIPT_SCHEMA, "result": "NO_DIAGNOSTIC_RECEIPT",
                "installation_comproved": False, "uac_approved": "NOT_ATTESTED"}
    if not path.is_file() or path.stat().st_size > 2048 or path.stat().st_size < 40:
        raise InstallBlocked("UAC_DIAGNOSTIC_READ_BLOCKED")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeError, ValueError, OSError):
        raise InstallBlocked("UAC_DIAGNOSTIC_READ_BLOCKED") from None
    if (not isinstance(record, dict) or record.get("schema") != UAC_RECEIPT_SCHEMA
        or record.get("host") != adm.HOST or record.get("environment") != "DEV"
        or record.get("diagnostic_only") is not True
        or record.get("phase") not in UAC_PHASES
        or record.get("operation") not in {"install", "rollback"}
        or record.get("uac_approved") != "NOT_ATTESTED"
        or record.get("installation_comproved") is not False
        or record.get("rollback_tested") is not False
        or record.get("detail") not in {"", "cancelled", "launch_error",
                                        "no_process_handle", "wait_timeout", "wait_failed",
                                        "wait_unexpected", "msi_nonzero", "reboot_required",
                                        "readback_missing", "exit_code_unavailable", "exit_zero"}
        or not isinstance(record.get("attempt_id"), str)
        or len(record["attempt_id"]) != 32
        or any(c not in "0123456789abcdef" for c in record["attempt_id"])
        or not isinstance(record.get("observed_at_utc"), str)
        or len(record["observed_at_utc"]) > 42):
        raise InstallBlocked("UAC_DIAGNOSTIC_READ_BLOCKED")
    # Expose only the typed, innocuous fields; do not echo arbitrary file data.
    return {"schema": UAC_RECEIPT_SCHEMA, "result": "DIAGNOSTIC_ONLY",
            "attempt_id": record["attempt_id"],
            "phase": record["phase"], "detail": str(record.get("detail") or "")[:30],
            "operation": record["operation"],
            "observed_at_utc": str(record.get("observed_at_utc") or "")[:42],
            "installation_comproved": False, "uac_approved": "NOT_ATTESTED",
            "rollback_tested": False}


def classify_wait_status(status: int) -> str:
    """Use documented Win32 wait codes; unknown codes must fail closed."""
    return {0: "completed", 258: "timeout", 0xffffffff: "failed"}.get(status, "unexpected")


def require_host() -> None:
    if os.name != "nt" or platform.system() != "Windows" or socket.gethostname().upper() != adm.HOST:
        raise InstallBlocked("HOST_NOT_RP23OGS_WINDOWS")
    if platform.machine().upper() not in ("AMD64", "X86_64"):
        raise InstallBlocked("CPU_NOT_AMD64")


def no_reparse(path: Path) -> None:
    for x in (path, *path.parents):
        if x.is_symlink() or getattr(x, "is_junction", lambda: False)():
            raise InstallBlocked("REPARSE_POINT_BLOCKED")


def fixed_cache() -> Path:
    require_host()
    local = os.environ.get("LOCALAPPDATA")
    if not local or not Path(local).is_absolute():
        raise InstallBlocked("LOCALAPPDATA_NOT_AVAILABLE")
    root = Path(local) / "PASS001" / "TailscaleInstallerV1"
    no_reparse(root)
    return root


def fixed_msi() -> Path:
    return fixed_cache() / "tailscale-pass001-staging" / adm.MSI_NAME


def preinstall_state() -> dict[str, bool]:
    """Only existence flags. Never read account state, identity, keys or registry values."""
    require_host()
    import winreg
    def registry_key_exists(hive, key):
        try:
            with winreg.OpenKey(hive, key, 0, winreg.KEY_READ):
                return True
        except FileNotFoundError:
            return False
        except OSError:
            raise InstallBlocked("WINDOWS_REGISTRY_READ_BLOCKED") from None
    def installed_record():
        for tree in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tree, 0, winreg.KEY_READ) as root:
                    i = 0
                    while i < 10000:
                        try:
                            child = winreg.EnumKey(root, i)
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                                break
                            raise InstallBlocked("WINDOWS_UNINSTALL_ENUMERATION_FAILED") from None
                        try:
                            with winreg.OpenKey(root, child, 0, winreg.KEY_READ) as sub:
                                name = str(winreg.QueryValueEx(sub, "DisplayName")[0])
                                if name.casefold().strip() == "tailscale":
                                    return True
                        except FileNotFoundError:
                            pass
                        except OSError:
                            raise InstallBlocked("WINDOWS_UNINSTALL_ENTRY_UNREADABLE") from None
                        i += 1
            except FileNotFoundError:
                continue
            except OSError:
                raise InstallBlocked("WINDOWS_UNINSTALL_INVENTORY_BLOCKED") from None
        return False
    local = Path(os.environ["LOCALAPPDATA"])
    program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
    p = {
        "service": registry_key_exists(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tailscale"),
        "uninstall": installed_record(),
        "program_files": ((Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Tailscale").exists()
                          or (Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Tailscale").exists()),
        "program_data": (program_data / "Tailscale").exists(),
        "user_data": (local / "Tailscale").exists(),
    }
    return p


def require_absent(state: dict[str, bool]) -> None:
    if set(state) != {"service", "uninstall", "program_files", "program_data", "user_data"}:
        raise InstallBlocked("BASELINE_INCOMPLETE")
    if any(state.values()):
        raise InstallBlocked("PREEXISTING_TAILSCALE_STATE_BLOCKED")


def read_verified_msi(path: Path) -> None:
    require_host()
    if path != fixed_msi() or not path.is_file():
        raise InstallBlocked("FIXED_MSI_NOT_READY")
    no_reparse(path)
    if adm.read_staged_msi(path, path.parent) != SOURCE_SHA:
        raise InstallBlocked("MSI_DIGEST_CHANGED")
    official = adm.parse_official_digest(evidence.get_official_digest())
    if official != SOURCE_SHA:
        raise InstallBlocked("OFFICIAL_CHECKSUM_CHANGED")
    if evidence.verify_windows_authenticode(path) is not True:
        raise InstallBlocked("AUTHENTICODE_NOT_VERIFIED")


def snapshot_path() -> Path:
    return fixed_cache() / "baseline.json"


def load_snapshot() -> dict:
    path = snapshot_path()
    no_reparse(path)
    if not path.is_file() or path.stat().st_size > 4096:
        raise InstallBlocked("BASELINE_BACKUP_MISSING")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise InstallBlocked("BASELINE_BACKUP_INVALID") from None
    if (not isinstance(data, dict) or data.get("contract") != CONTRACT or
        data.get("msi_sha256") != SOURCE_SHA or data.get("host") != adm.HOST or
        data.get("environment") != "DEV" or data.get("preinstall") is None):
        raise InstallBlocked("BASELINE_BACKUP_SCOPE_MISMATCH")
    require_absent(data["preinstall"])
    return data


def prepare() -> dict:
    """Risk2: verify official MSI in this worktree, back it up; never install."""
    require_host()
    source = Path.cwd() / "tailscale-pass001-staging" / adm.MSI_NAME
    no_reparse(source)
    if not source.is_file():
        staging.stage_once(worktree=Path.cwd())
    if adm.read_staged_msi(source, source.parent) != SOURCE_SHA:
        raise InstallBlocked("SOURCE_MSI_HASH_MISMATCH")
    if evidence.verify_windows_authenticode(source) is not True:
        raise InstallBlocked("SOURCE_MSI_SIGNER_INVALID")
    official = adm.parse_official_digest(evidence.get_official_digest())
    if official != SOURCE_SHA:
        raise InstallBlocked("OFFICIAL_DIGEST_MISMATCH")
    state = preinstall_state()
    require_absent(state)
    cache = fixed_cache()
    target = fixed_msi()
    target.parent.mkdir(parents=True, exist_ok=True)
    no_reparse(target)
    if target.exists():
        read_verified_msi(target)
        if not snapshot_path().is_file():
            raise InstallBlocked("BACKUP_COLLISION")
        if load_snapshot()["preinstall"] != state:
            raise InstallBlocked("BASELINE_CHANGED")
        replay = True
    else:
        # Fixed location, exclusive write, validate copied bytes before any commit.
        try:
            with source.open("rb") as f, target.open("xb") as out:
                while chunk := f.read(1024 * 1024):
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            read_verified_msi(target)
            baseline = {"contract": CONTRACT, "host": adm.HOST, "environment": "DEV",
                        "version": adm.VERSION, "msi_sha256": SOURCE_SHA, "preinstall": state,
                        "rollback": "SAME_SIGNED_MSI_UNINSTALL_ONLY", "rollback_tested": False}
            with snapshot_path().open("x", encoding="utf-8") as out:
                json.dump(baseline, out, sort_keys=True)
                out.flush()
                os.fsync(out.fileno())
            if load_snapshot() != baseline:
                raise InstallBlocked("BACKUP_READBACK_MISMATCH")
        except BaseException:
            # Do not overwrite or delete an ambiguous destination on failure.
            raise
        replay = False
    # Remove only the single known staging artifact after durable backup readback.
    # This leaves the Risk3 source worktree clean and prevents the UAC gate from
    # being bypassed with a hidden/ignored untracked MSI.
    source.unlink()
    source.parent.rmdir()
    return {"result": "BACKUP_SOURCE_AND_EMPTY_BASELINE_VERIFIED", "replayed": replay,
            "msi_sha256": SOURCE_SHA, "installed": False, "uac_executed": False}


def preflight() -> dict:
    require_host()
    if not fixed_msi().is_file():
        raise InstallBlocked("MSI_BACKUP_NOT_PRESENT")
    snap = load_snapshot()
    read_verified_msi(fixed_msi())
    now = preinstall_state()
    require_absent(now)
    if now != snap["preinstall"]:
        raise InstallBlocked("BASELINE_CHANGED")
    return {"result": "READY_FOR_EXACT_UAC_ACTION_NOT_INSTALLED", "host": adm.HOST,
            "msi_sha256": SOURCE_SHA, "backup_readback": True,
            "baseline_absent": True, "rollback_tested": False,
            "install_executed": False, "tailnet_activated": False}


def build_msiexec_args(operation: str, msi: Path) -> str:
    if operation == "install":
        action = "/i"
        extra = ' TS_NOLAUNCH=1 TS_UNATTENDEDMODE=never'
    elif operation == "rollback":
        action = "/x"
        extra = ""
    else:
        raise InstallBlocked("OPERATION_DENIED")
    # Fixed arguments; no arbitrary paths or commands from caller.
    return f'{action} "{msi}" /qn /norestart{extra}'


def is_admin() -> bool:
    try:
        return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False



def require_specific_risk3_action(operation: str, confirm: str) -> None:
    """Deny Risk2 direct invocation, even if caller supplies the public confirm.

    Requires the existing owner-only private Risk3 allowlist, bound to this
    script, its bytes, the clean exact Git checkout, host and short expiry.
    Never accepts development-mode/broad allowlist as authority.
    """
    require_host()
    action_id = RISK3_IDS.get(operation)
    if not action_id:
        raise InstallBlocked("RISK3_OPERATION_DENIED")
    path = Path(os.environ["LOCALAPPDATA"]) / "ReqSys" / "CommandGateway" / "owner-risk3-exceptions.local.json"
    no_reparse(path)
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise InstallBlocked("RISK3_EXACT_ACTION_REQUIRED") from None
    actor = hashlib.sha256(f"{getpass.getuser()}@{socket.gethostname()}".encode("utf-8", errors="replace")).hexdigest()
    if cfg.get("version") != 1 or cfg.get("enabled") is not True or cfg.get("owner_fingerprint") != actor:
        raise InstallBlocked("RISK3_OWNER_SCOPE_MISMATCH")
    action = (cfg.get("actions") or {}).get(action_id)
    if not isinstance(action, dict) or action.get("environment") != "dev" or action.get("scope") != RISK3_SCOPE:
        raise InstallBlocked("RISK3_EXACT_ACTION_REQUIRED")
    try:
        expires = datetime.fromisoformat(str(action["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        raise InstallBlocked("RISK3_ACTION_EXPIRED") from None
    if expires.tzinfo is None or expires.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        raise InstallBlocked("RISK3_ACTION_EXPIRED")
    actual_script = Path(__file__).resolve(strict=True)
    expected = [sys.executable, str(actual_script), f"--{operation}", "--confirm", confirm]
    if action.get("command") != expected:
        raise InstallBlocked("RISK3_COMMAND_NOT_EXACT")
    if Path(str(action.get("cwd") or "")).resolve() != Path.cwd().resolve():
        raise InstallBlocked("RISK3_WORKTREE_NOT_BOUND")
    expected_sha = str(action.get("script_sha256") or "")
    if expected_sha != hashlib.sha256(actual_script.read_bytes()).hexdigest():
        raise InstallBlocked("RISK3_SCRIPT_DIGEST_MISMATCH")
    expected_head = str(action.get("git_head") or "")
    if len(expected_head) != 40:
        raise InstallBlocked("RISK3_HEAD_INVALID")
    for git_command, expected_output in [(["rev-parse", "HEAD"], expected_head),
                                         (["rev-parse", "--show-toplevel"], str(Path.cwd()))]:
        cp = subprocess.run(["git", *git_command], cwd=Path.cwd(), shell=False,
                            capture_output=True, text=True, timeout=15, check=False)
        if cp.returncode or (git_command[0] == "rev-parse" and
                            ((cp.stdout.strip().casefold() != expected_output.casefold()) if git_command[1] == "HEAD"
                             else (Path(cp.stdout.strip()).resolve() != Path.cwd().resolve()))):
            raise InstallBlocked("RISK3_GIT_BINDING_MISMATCH")
    clean = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"],
                           cwd=Path.cwd(), shell=False, capture_output=True, text=True,
                           timeout=15, check=False)
    if clean.returncode or clean.stdout.strip() or clean.stderr.strip():
        raise InstallBlocked("RISK3_WORKTREE_DIRTY")


def request_uac(operation: str, confirm: str) -> dict:
    """Risk3 exact action only; OS UAC prompt must be accepted by a human."""
    if operation == "install":
        if confirm != CONFIRM_INSTALL:
            raise InstallBlocked("INSTALL_CONFIRMATION_INVALID")
        preflight()
    elif operation == "rollback":
        if confirm != CONFIRM_ROLLBACK:
            raise InstallBlocked("ROLLBACK_CONFIRMATION_INVALID")
        load_snapshot()
        read_verified_msi(fixed_msi())
        before_rollback = preinstall_state()
        if not any(before_rollback.get(k, False) for k in ("service", "uninstall", "program_files", "program_data")):
            raise InstallBlocked("NO_INSTALLED_STATE_FOR_ROLLBACK")
    else:
        raise InstallBlocked("OPERATION_DENIED")
    require_specific_risk3_action(operation, confirm)
    if not INSTALLER.is_file() or INSTALLER.parent != Path(r"C:\Windows\System32"):
        raise InstallBlocked("SYSTEM_MSIEC_UNAVAILABLE")
    if is_admin():
        raise InstallBlocked("ALREADY_ELEVATED_REQUIRES_SEPARATE_SESSION_GATE")
    previous = read_uac_diagnostic()
    if previous["result"] == "DIAGNOSTIC_ONLY" and previous["phase"] != "postcondition_verified":
        raise InstallBlocked("PREVIOUS_UAC_ATTEMPT_UNRESOLVED")
    attempt_id = uuid.uuid4().hex
    diagnostic_update_failed = False

    def checkpoint(phase: str, detail: str = "") -> None:
        nonlocal diagnostic_update_failed
        # Once UAC may have started, NEVER abandon the process handle just
        # because diagnostic metadata could not be written to LOCALAPPDATA.
        try:
            write_uac_diagnostic(operation, attempt_id, phase, detail=detail)
        except (OSError, InstallBlocked):
            diagnostic_update_failed = True

    # Keep a Windows file handle with no WRITE/DELETE sharing through launch.
    # The user-owned MSI cannot be replaced during the UAC confirmation window.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    handle = kernel.CreateFileW(str(fixed_msi()), 0x80000000, 1, None, 3, 0x80, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise InstallBlocked("MSI_FILE_LOCK_UNAVAILABLE")
    try:
        read_verified_msi(fixed_msi())
        # ShellExecuteEx gives a process handle for exact msiexec, not a shell.
        from ctypes import wintypes
        class EXEC(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong),
                        ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                        ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                        ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                        ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                        ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                        ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE),
                        ("hProcess", wintypes.HANDLE)]
        exe = EXEC()
        exe.cbSize = ctypes.sizeof(EXEC)
        exe.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
        exe.lpVerb = "runas"
        exe.lpFile = str(INSTALLER)
        exe.lpParameters = build_msiexec_args(operation, fixed_msi())
        exe.lpDirectory = str(Path.cwd())
        exe.nShow = 1  # SW_SHOWNORMAL; never automate UAC interaction
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        shell.ShellExecuteExW.argtypes = [ctypes.POINTER(EXEC)]
        shell.ShellExecuteExW.restype = wintypes.BOOL
        # This MUST be durable before asking Windows to start elevated MSI.
        write_uac_diagnostic(operation, attempt_id, "launch_requested")
        if not shell.ShellExecuteExW(ctypes.byref(exe)):
            err = ctypes.get_last_error()
            checkpoint("launch_rejected",
                                 detail="cancelled" if err == 1223 else "launch_error")
            raise InstallBlocked("UAC_REJECTED_OR_UNAVAILABLE" if err == 1223 else "UAC_LAUNCH_FAILED")
        if not exe.hProcess:
            checkpoint("launch_rejected", detail="no_process_handle")
            raise InstallBlocked("ELEVATED_PROCESS_HANDLE_MISSING")
        checkpoint("elevated_process_handle_received")
        try:
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.WaitForSingleObject.restype = wintypes.DWORD
            checkpoint("wait_started")
            wait_result = classify_wait_status(int(kernel.WaitForSingleObject(exe.hProcess, 120000)))
            if wait_result != "completed":
                # DO NOT terminate an elevated process: it may still be mutating
                # system state. Do not retry until independent physical readback.
                checkpoint(
                    "wait_timeout_process_may_continue" if wait_result == "timeout" else "wait_failed",
                    detail={"timeout": "wait_timeout", "failed": "wait_failed",
                            "unexpected": "wait_unexpected"}[wait_result],
                )
                raise InstallBlocked("UAC_MSI_PROCESS_NOT_COMPLETED")
            code = wintypes.DWORD()
            kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            if not kernel.GetExitCodeProcess(exe.hProcess, ctypes.byref(code)):
                checkpoint("wait_failed", detail="exit_code_unavailable")
                raise InstallBlocked("UAC_EXIT_CODE_UNAVAILABLE")
            checkpoint("process_exited",
                                 detail="exit_zero" if code.value == 0 else
                                        "reboot_required" if code.value == 3010 else "msi_nonzero")
            if code.value not in (0, 3010):
                raise InstallBlocked("MSI_OPERATION_FAILED")
            if code.value == 3010:
                raise InstallBlocked("MSI_REBOOT_REQUIRED_NOT_AUTHORIZED")
        finally:
            kernel.CloseHandle(exe.hProcess)
    finally:
        kernel.CloseHandle(handle)
    after = preinstall_state()
    if operation == "install":
        if not (after["service"] and after["uninstall"] and after["program_files"]):
            checkpoint("postcondition_failed", detail="readback_missing")
            raise InstallBlocked("INSTALL_POSTCONDITION_NOT_PROVEN")
        checkpoint("postcondition_verified")
        if diagnostic_update_failed:
            raise InstallBlocked("UAC_DIAGNOSTIC_UPDATE_FAILED")
        return {"result": "INSTALLED_NOT_LOGGED_IN", "msi_sha256": SOURCE_SHA,
                "service_present": True, "login_attempted": False, "tailnet_activated": False,
                "rollback_tested": False}
    if any(after.values()):
        # The MSI uninstall can preserve ProgramData; do not erase data or claim rollback.
        checkpoint("postcondition_failed", detail="readback_missing")
        raise InstallBlocked("ROLLBACK_POSTCONDITION_INCOMPLETE")
    checkpoint("postcondition_verified")
    if diagnostic_update_failed:
        raise InstallBlocked("UAC_DIAGNOSTIC_UPDATE_FAILED")
    return {"result": "ROLLBACK_BASELINE_RESTORED", "rollback_tested": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mx = parser.add_mutually_exclusive_group(required=True)
    for flag in ("prepare", "preflight", "install", "rollback", "verify", "diagnose"):
        mx.add_argument("--" + flag, action="store_true")
    parser.add_argument("--confirm", default="")
    ns = parser.parse_args(argv)
    try:
        if ns.prepare:
            if ns.confirm:
                raise InstallBlocked("EXTRA_CONFIRMATION_DENIED")
            result = prepare()
        elif ns.preflight:
            result = preflight()
        elif ns.install:
            result = request_uac("install", ns.confirm)
        elif ns.rollback:
            result = request_uac("rollback", ns.confirm)
        elif ns.diagnose:
            if ns.confirm:
                raise InstallBlocked("EXTRA_CONFIRMATION_DENIED")
            result = read_uac_diagnostic()
        else:
            if ns.confirm:
                raise InstallBlocked("EXTRA_CONFIRMATION_DENIED")
            st = preinstall_state()
            result = {"result": "STATE_OBSERVED", "host": adm.HOST,
                      "service_present": st["service"], "uninstall_present": st["uninstall"],
                      "program_files_present": st["program_files"],
                      "has_prior_or_new_data": st["user_data"] or st["program_data"]}
    except (InstallBlocked, adm.AdmissionBlocked, evidence.EvidenceBlocked, OSError, ValueError) as exc:
        safe = str(exc)
        if safe not in {"HOST_NOT_RP23OGS_WINDOWS", "CPU_NOT_AMD64", "PREEXISTING_TAILSCALE_STATE_BLOCKED",
                        "BACKUP_COLLISION", "WORKTREE_MSI_NOT_STAGED", "MSI_BACKUP_NOT_PRESENT",
                        "OFFICIAL_DIGEST_MISMATCH", "SOURCE_MSI_HASH_MISMATCH", "SOURCE_MSI_SIGNER_INVALID",
                        "INSTALL_CONFIRMATION_INVALID", "ROLLBACK_CONFIRMATION_INVALID", "NO_INSTALLED_SERVICE_FOR_ROLLBACK",
                        "BASELINE_CHANGED", "MSI_OPERATION_FAILED", "MSI_REBOOT_REQUIRED_NOT_AUTHORIZED",
                        "UAC_REJECTED_OR_UNAVAILABLE", "UAC_LAUNCH_FAILED", "UAC_MSI_PROCESS_NOT_COMPLETED",
                        "ROLLBACK_POSTCONDITION_INCOMPLETE", "UAC_DIAGNOSTIC_READ_BLOCKED",
                        "UAC_DIAGNOSTIC_TARGET_INVALID",
                        "PREVIOUS_UAC_ATTEMPT_UNRESOLVED", "UAC_DIAGNOSTIC_UPDATE_FAILED"}:
            safe = "PRECONDITION_OR_VERIFICATION_FAILED"
        print(json.dumps({"contract": CONTRACT, "result": "BLOCKED", "reason": safe,
                          "installation_comproved": False}, sort_keys=True))
        return EXIT_BLOCK
    print(json.dumps({"contract": CONTRACT, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
