#!/usr/bin/env python3
"""Plan, then explicitly approve only the fixed owner DEV prepare grant, at most 1h.

Default is read-only. This never enables development_mode or changes gateway policy.
"""
from __future__ import annotations

import argparse
import copy
import ctypes
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys

class OperationError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

HOST = "DESKTOP-PDQK954"
REPOSITORY = "ericson-j-santos/reqsys-v2-enterprise-real"
REMOTE = "https://github.com/" + REPOSITORY + ".git"
WORKERS = Path("C:/dev/chatgpt-workers")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
LAUNCHER = "scripts/run_self_hosted_dev_owner_action.py"
SCRIPTS = {"prepare": "scripts/reqsys_self_hosted_dev_publish.py"}
ACTION_IDS = {"prepare": "reqsys.selfhost.publisher.prepare.dev"}
SCOPES = {"prepare": "repo://reqsys/environment/dev/selfhost"}

def require_hex(value, expression, code):
    if not isinstance(value, str) or not expression.fullmatch(value):
        raise OperationError(code)
    return value

def no_reparse(path):
    path = Path(path)
    for current in (path, *path.parents):
        info = current.lstat()
        if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise OperationError("reparse_path_blocked")
    if path.is_file() and path.stat().st_nlink != 1:
        raise OperationError("hardlink_path_blocked")

def require_host():
    if os.name != "nt" or socket.gethostname().casefold() != HOST.casefold():
        raise OperationError("fixed_windows_host_required")

def file_digest(path):
    no_reparse(path)
    if not path.is_file() or path.stat().st_size > 1048576:
        raise OperationError("script_size_or_type_invalid")
    return hashlib.sha256(path.read_bytes()).hexdigest()

def source_root(expected_sha):
    require_hex(expected_sha, SHA, "invalid_source_sha")
    return WORKERS / ("rs2-" + expected_sha)

def git_read(root, args):
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_"):
            environment.pop(name)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    result = subprocess.run(
        ["git", "-c", "core.longpaths=true", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        shell=False, capture_output=True, text=True, encoding="utf-8",
        errors="strict", timeout=30, check=False, env=environment,
    )
    if result.returncode or result.stderr.strip() or len(result.stdout) > 2097152:
        raise OperationError("source_git_validation_failed")
    return result.stdout.rstrip("\r\n")

def validate_repository(root, expected_sha):
    no_reparse(root)
    if not root.is_dir():
        raise OperationError("source_root_missing")
    actual = Path(git_read(root, ["rev-parse", "--show-toplevel"])).resolve()
    if actual != root.resolve():
        raise OperationError("source_root_mismatch")
    if git_read(root, ["remote", "get-url", "origin"]) != REMOTE:
        raise OperationError("source_origin_mismatch")
    if git_read(root, ["rev-parse", "HEAD"]) != expected_sha:
        raise OperationError("source_head_mismatch")
    if git_read(root, ["status", "--porcelain", "--untracked-files=all"]):
        raise OperationError("source_tree_dirty")
    records = git_read(root, ["ls-files", "-v"]).splitlines()
    if not records or any(not row.startswith("H ") for row in records):
        raise OperationError("source_index_flags_untrusted")

def validate_scripts(root, script_digests):
    for relative, digest in script_digests.items():
        require_hex(digest, DIGEST, "invalid_script_sha256")
        if relative not in {*SCRIPTS.values(), LAUNCHER}:
            raise OperationError("script_not_closed")
        if git_read(root, ["ls-files", "--error-unmatch", relative]) != relative:
            raise OperationError("script_not_tracked")
        if file_digest(root / relative) != digest:
            raise OperationError("script_sha256_mismatch")

def python_executable():
    path = Path(sys.executable)
    if not path.is_absolute() or path.name.casefold() not in ("python.exe", "python3.exe"):
        raise OperationError("absolute_python_executable_required")
    no_reparse(path)
    if not path.is_file():
        raise OperationError("python_executable_missing")
    return str(path)

CONFIG_ROOT = Path("C:/Users/Windows/AppData/Local/ReqSys/CommandGateway")
CONFIG_NAME = "owner-risk3-exceptions.local.json"
# Keep the reviewed launcher schema; its phase lookup needs no receiver grant.
GRANT_CONTRACT = "reqsys-selfhost-dev-two-actions-one-hour-v1"
APPLY_CONFIRM = "GRANT-REQSYS-DEV-PREPARE-ONE-HOUR"
RENEW_CONFIRM = "RENEW-REQSYS-DEV-PREPARE-ONE-HOUR"
MAX_CONFIG_BYTES = 262144

class WindowsPrivateFiles:
    """DACL protegida: somente usuário atual e SYSTEM; sem shell."""

    def __init__(self):
        if os.name != "nt":
            raise OperationError("windows_acl_required")
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.adv.OpenProcessToken.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
        ]
        self.adv.GetTokenInformation.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
        ]
        self.adv.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
        ]
        self.adv.ConvertStringSidToSidW.argtypes = [
            wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)
        ]
        self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)
        ]
        self.adv.SetFileSecurityW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p
        ]
        self.adv.GetFileSecurityW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
        ]
        self.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)
        ]
        self.sid = self._user_sid()
        self.sddl = f"O:{self.sid}D:P(A;;FA;;;{self.sid})(A;;FA;;;SY)"
        self.directory_sddl = f"O:{self.sid}D:P(A;OICI;FA;;;{self.sid})(A;OICI;FA;;;SY)"

    def _canonical_sid(self, value: str) -> str:
        """Compara SID real, independentemente do alias usado pelo SDDL."""
        sid = ctypes.c_void_p()
        if not self.adv.ConvertStringSidToSidW(value, ctypes.byref(sid)):
            raise OperationError("private_acl_sid_invalid")
        text = ctypes.c_void_p()
        try:
            if not self.adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                raise OperationError("private_acl_sid_invalid")
            try:
                return ctypes.wstring_at(text)
            finally:
                self.kernel.LocalFree(text)
        finally:
            self.kernel.LocalFree(sid)

    def _user_sid(self) -> str:
        token = wintypes.HANDLE()
        if not self.adv.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)
        ):
            raise OperationError("private_acl_identity_failed")
        try:
            size = wintypes.DWORD()
            self.adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            if not self.adv.GetTokenInformation(
                token, 1, buffer, size.value, ctypes.byref(size)
            ):
                raise OperationError("private_acl_identity_failed")
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
            text = ctypes.c_void_p()
            if not self.adv.ConvertSidToStringSidW(sid, ctypes.byref(text)):
                raise OperationError("private_acl_identity_failed")
            try:
                return ctypes.wstring_at(text)
            finally:
                self.kernel.LocalFree(text)
        finally:
            self.kernel.CloseHandle(token)

    def secure(self, path: Path) -> None:
        no_reparse(path)
        descriptor = ctypes.c_void_p()
        if not self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            self.directory_sddl if path.is_dir() else self.sddl,
            1, ctypes.byref(descriptor), None
        ):
            raise OperationError("private_acl_descriptor_failed")
        try:
            if not self.adv.SetFileSecurityW(
                str(path), 0x80000005, descriptor
            ):
                raise OperationError("private_acl_write_failed")
        finally:
            self.kernel.LocalFree(descriptor)
        self.check(path)

    def check(self, path: Path) -> None:
        no_reparse(path)
        size = wintypes.DWORD()
        self.adv.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(size))
        if not size.value:
            raise OperationError("private_acl_read_failed")
        descriptor = ctypes.create_string_buffer(size.value)
        if not self.adv.GetFileSecurityW(
            str(path), 5, descriptor, size.value, ctypes.byref(size)
        ):
            raise OperationError("private_acl_read_failed")
        text = ctypes.c_void_p()
        if not self.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 5, ctypes.byref(text), None
        ):
            raise OperationError("private_acl_read_failed")
        try:
            value = ctypes.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)
        flags = r"(?:OICI)?" if path.is_dir() else ""
        match = re.fullmatch(r"O:([^:]+)D:P(?:AI)?((?:\(A;" + flags + r";FA;;;[^)]+\)){2})", value)
        if not match or self._canonical_sid(match.group(1)) != self._canonical_sid(self.sid):
            raise OperationError("private_acl_not_exclusive")
        identities = re.findall(r"\(A;" + flags + r";FA;;;([^)]+)\)", match.group(2))
        normalized = [self._canonical_sid(identity) for identity in identities]
        expected = (self._canonical_sid(self.sid), self._canonical_sid("SY"))
        if sorted(normalized) != sorted(expected):
            raise OperationError("private_acl_not_exclusive")


    def check_readable(self, path: Path) -> None:
        """Read legacy owner/SYSTEM/Administrators only; never changes its DACL."""
        no_reparse(path)
        if not path.is_file():
            raise OperationError("configuration_acl_untrusted")
        size = wintypes.DWORD()
        self.adv.GetFileSecurityW(str(path), 5, None, 0, ctypes.byref(size))
        if not size.value or size.value > 65536:
            raise OperationError("configuration_acl_unavailable")
        descriptor = ctypes.create_string_buffer(size.value)
        if not self.adv.GetFileSecurityW(
            str(path), 5, descriptor, size.value, ctypes.byref(size)
        ):
            raise OperationError("configuration_acl_unavailable")
        text = ctypes.c_void_p()
        if not self.adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 5, ctypes.byref(text), None
        ):
            raise OperationError("configuration_acl_unavailable")
        try:
            value = ctypes.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)
        match = re.fullmatch(r"O:([^:]+)D:(?:P)?(?:AR)?(?:AI)?((?:\([^()]+\))+)", value)
        if not match or self._canonical_sid(match.group(1)) != self._canonical_sid(self.sid):
            raise OperationError("configuration_acl_untrusted")
        allowed = {
            self._canonical_sid(self.sid),
            self._canonical_sid("SY"),
            self._canonical_sid("BA"),
        }
        entries = re.findall(r"\(([^()]*)\)", match.group(2))
        if not entries or len(entries) > 64:
            raise OperationError("configuration_acl_untrusted")
        actual = set()
        for entry in entries:
            fields = entry.split(";")
            if len(fields) != 6 or fields[0] != "A" or fields[3] or fields[4]:
                raise OperationError("configuration_acl_untrusted")
            if not re.fullmatch(r"(?:OI|CI|NP|IO|ID)*", fields[1]):
                raise OperationError("configuration_acl_untrusted")
            if not re.fullmatch(r"(?:0x[0-9a-fA-F]+|(?:FA|FR|FW|FX|RC|SD|WD|WO|GR|GW|GX|GA)+)", fields[2]):
                raise OperationError("configuration_acl_untrusted")
            identity = self._canonical_sid(fields[5])
            if identity not in allowed:
                raise OperationError("configuration_acl_untrusted")
            actual.add(identity)
        if self._canonical_sid(self.sid) not in actual:
            raise OperationError("configuration_acl_untrusted")


def owner_fingerprint():
    identity = f"{getpass.getuser()}@{socket.gethostname()}".encode(
        "utf-8", errors="replace"
    )
    return hashlib.sha256(identity).hexdigest()

def require_owner():
    require_host()
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.GetUserNameW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    size = wintypes.DWORD(256)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not adv.GetUserNameW(buffer, ctypes.byref(size)):
        raise OperationError("windows_owner_identity_unavailable")
    if buffer.value.casefold() != "windows" or getpass.getuser().casefold() != "windows":
        raise OperationError("windows_owner_mismatch")
    local = os.environ.get("LOCALAPPDATA", "")
    if not local or Path(local).resolve() != CONFIG_ROOT.parent.parent.resolve():
        raise OperationError("fixed_localappdata_required")

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise OperationError("configuration_duplicate_key")
        result[key] = value
    return result

def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False
    ).encode("ascii")

def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()

def validate_config(config, fingerprint):
    if not isinstance(config, dict) or type(config.get("version")) is not int or config["version"] != 1:
        raise OperationError("existing_version_one_configuration_required")
    if config.get("enabled") is not True:
        raise OperationError("existing_owner_gateway_must_be_enabled")
    if config.get("owner_fingerprint") != fingerprint:
        raise OperationError("configuration_owner_mismatch")
    if not isinstance(config.get("actions"), dict):
        raise OperationError("existing_actions_object_required")
    mode = config.get("development_mode")
    if "development_mode" in config and (not isinstance(mode, dict) or mode.get("enabled") is not False):
        raise OperationError("broad_development_mode_must_remain_disabled")

def read_config(path, private):
    no_reparse(path)
    if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
        raise OperationError("configuration_size_or_type_invalid")
    private.check_readable(path)
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise OperationError("configuration_too_large")
    config = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)
    validate_config(config, owner_fingerprint())
    return raw, config

def parse_utc(value):
    if not isinstance(value, str):
        raise OperationError("grant_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise OperationError("grant_timestamp_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise OperationError("grant_utc_required")
    return parsed

def hour_window(now):
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise OperationError("plan_utc_required")
    start = now.replace(minute=0, second=0, microsecond=0)
    return start, start + timedelta(hours=1)

def command_for(phase, source_sha, script_sha256, python):
    if phase not in SCRIPTS:
        raise OperationError("phase_not_closed")
    root = source_root(source_sha)
    require_hex(script_sha256, DIGEST, "invalid_script_sha256")
    return [
        python, str(root / LAUNCHER), phase,
        "--source-sha", source_sha, "--script-sha256", script_sha256,
    ]

def grant_for(phase, source_sha, script_sha256, launcher_sha256, python,
              start, expiry):
    return {
        "environment": "dev", "scope": SCOPES[phase],
        "valid_from": start.isoformat(), "expires_at": expiry.isoformat(),
        "command": command_for(phase, source_sha, script_sha256, python),
        "grant_contract": GRANT_CONTRACT, "source_sha": source_sha,
        "script_sha256": script_sha256, "launcher_sha256": launcher_sha256,
    }

def validate_owned_grant(phase, grant, python):
    if not isinstance(grant, dict):
        raise OperationError("existing_action_collision")
    if grant.get("grant_contract") != GRANT_CONTRACT:
        raise OperationError("existing_action_collision")
    start = parse_utc(grant.get("valid_from"))
    expiry = parse_utc(grant.get("expires_at"))
    if start.minute or start.second or start.microsecond:
        raise OperationError("existing_grant_window_invalid")
    if expiry - start != timedelta(hours=1):
        raise OperationError("existing_grant_window_invalid")
    expected = grant_for(
        phase,
        require_hex(grant.get("source_sha"), SHA, "existing_source_sha_invalid"),
        require_hex(grant.get("script_sha256"), DIGEST, "existing_script_sha_invalid"),
        require_hex(grant.get("launcher_sha256"), DIGEST, "existing_launcher_sha_invalid"),
        python, start, expiry,
    )
    if grant != expected:
        raise OperationError("existing_action_collision")
    return start, expiry

def build_plan(config, config_bytes, source_sha, digests, launcher_sha256, python, now):
    require_hex(source_sha, SHA, "invalid_source_sha")
    require_hex(launcher_sha256, DIGEST, "invalid_launcher_sha256")
    if set(digests) != set(SCRIPTS):
        raise OperationError("exact_prepare_script_digest_required")
    for digest in digests.values():
        require_hex(digest, DIGEST, "invalid_script_sha256")
    start, expiry = hour_window(now)
    actions = config["actions"]
    present = [ACTION_IDS[phase] in actions for phase in SCRIPTS]
    operation = "add"
    if any(present):
        if not all(present):
            raise OperationError("partial_existing_grants_blocked")
        windows = [
            validate_owned_grant(phase, actions[ACTION_IDS[phase]], python)
            for phase in SCRIPTS
        ]
        if any(window != windows[0] for window in windows):
            raise OperationError("existing_grant_windows_diverge")
        existing_start, existing_expiry = windows[0]
        same_binding = all(
            actions[ACTION_IDS[phase]] == grant_for(
                phase, source_sha, digests[phase], launcher_sha256,
                python, existing_start, existing_expiry,
            ) for phase in SCRIPTS
        )
        if existing_expiry > now:
            if not same_binding:
                raise OperationError("active_grants_bound_to_other_source")
            operation = "replay"
            start, expiry = existing_start, existing_expiry
        else:
            operation = "renew"
    proposed = copy.deepcopy(config)
    changes = {}
    for phase in SCRIPTS:
        action_id = ACTION_IDS[phase]
        proposed["actions"][action_id] = grant_for(
            phase, source_sha, digests[phase], launcher_sha256, python, start, expiry
        )
        changes[action_id] = {
            "before_sha256": sha256_bytes(canonical(actions.get(action_id))),
            "after_sha256": sha256_bytes(canonical(proposed["actions"][action_id])),
        }
    diff_sha256 = sha256_bytes(canonical(changes))
    plan_sha256 = sha256_bytes(canonical({
        "contract": GRANT_CONTRACT,
        "before_bytes_sha256": sha256_bytes(config_bytes),
        "proposed_sha256": sha256_bytes(canonical(proposed)),
        "diff_sha256": diff_sha256,
        "operation": operation,
    }))
    evidence = {
        "status": "planned", "read_only": True, "operation": operation,
        "changes_required": operation != "replay",
        "plan_sha256": plan_sha256, "diff_sha256": diff_sha256,
        "source_sha": source_sha, "launcher_sha256": launcher_sha256,
        "expires_at": expiry.isoformat(), "maximum_validity_seconds": 3600,
        "development_mode_changed": False,
        "configuration_file_acl_after": "protected_current_owner_and_system_only",
        "shared_directory_acl_changed": False,
        "approval_required": operation != "replay",
        "actions": [
            {
                "action_id": ACTION_IDS[phase], "scope": SCOPES[phase],
                "script_sha256": digests[phase], "expires_at": expiry.isoformat(),
            } for phase in SCRIPTS
        ],
    }
    return proposed, evidence

def authorize_apply(evidence, confirm, reviewed_plan_sha256, renew_expired):
    require_hex(reviewed_plan_sha256, DIGEST, "reviewed_plan_sha256_required")
    if reviewed_plan_sha256 != evidence["plan_sha256"]:
        raise OperationError("reviewed_plan_changed")
    renewal = evidence["operation"] == "renew"
    if bool(renew_expired) != renewal:
        raise OperationError("explicit_expired_renewal_required")
    expected = RENEW_CONFIRM if renewal else APPLY_CONFIRM
    if confirm != expected:
        raise OperationError("closed_apply_confirmation_required")

def atomic_apply(path, private, original, proposed):
    no_reparse(path)
    private.check_readable(path)
    temporary = path.with_name("." + CONFIG_NAME + "." + secrets.token_hex(8) + ".tmp")
    fd = -1
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        # The new file contains no bytes before its protected DACL is verified.
        private.secure(temporary)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(canonical(proposed) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        private.check(temporary)
        no_reparse(path)
        private.check_readable(path)
        if path.read_bytes() != original:
            raise OperationError("configuration_changed_during_review")
        os.replace(temporary, path)
        private.check(path)
    finally:
        if fd != -1:
            os.close(fd)
        if temporary.exists():
            temporary.unlink()

def validate_source_bundle(source_sha, digests, launcher_sha256):
    root = source_root(source_sha)
    validate_repository(root, source_sha)
    validate_scripts(root, {
        LAUNCHER: launcher_sha256,
        SCRIPTS["prepare"]: digests["prepare"],
    })
    return root

def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--prepare-script-sha256", required=True)
    parser.add_argument("--launcher-script-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--reviewed-plan-sha256", default="")
    parser.add_argument("--renew-expired", action="store_true")
    return parser

def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if not args.apply and (args.confirm or args.reviewed_plan_sha256 or args.renew_expired):
            raise OperationError("apply_only_options_require_apply")
        require_owner()
        digests = {
            "prepare": args.prepare_script_sha256,
        }
        validate_source_bundle(args.source_sha, digests, args.launcher_script_sha256)
        python = python_executable()
        private = WindowsPrivateFiles()
        path = CONFIG_ROOT / CONFIG_NAME
        original, config = read_config(path, private)
        proposed, evidence = build_plan(
            config, original, args.source_sha, digests, args.launcher_script_sha256,
            python, datetime.now(timezone.utc),
        )
        if args.apply:
            authorize_apply(
                evidence, args.confirm, args.reviewed_plan_sha256, args.renew_expired
            )
            if evidence["changes_required"]:
                atomic_apply(path, private, original, proposed)
            evidence.update({"status": "applied", "read_only": False})
        print(json.dumps(evidence, sort_keys=True))
        return 0
    except Exception as exc:
        code = exc.code if isinstance(exc, OperationError) else "registry_operation_failed"
        print(json.dumps({"status": "blocked", "code": code}, sort_keys=True))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
