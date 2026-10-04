#!/usr/bin/env python3
"""Read only the fixed ReqSys runner's public registration metadata on PC24x7."""
from __future__ import annotations
import argparse
import ctypes
import datetime as dt
import json
import os
from pathlib import Path
import re
import socket
import stat

HOST = "DESKTOP-PDQK954"
CALLER_REPOSITORY = "ericson-j-santos/desktop-pc24x7-runtime"
EXPECTED_REPOSITORY_URL = "https://github.com/ericson-j-santos/reqsys-v2-enterprise-real"
MAX_METADATA_BYTES = 32768

class ProbeError(RuntimeError):
    pass

def checked_path(path: Path, *, directory: bool = False) -> Path:
    # Reject every redirecting component before opening the one public file.
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except OSError:
            raise ProbeError("EXPECTED_RUNNER_PATH_MISSING") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ProbeError("RUNNER_PATH_REPARSE_REJECTED")
    info = path.lstat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ProbeError("RUNNER_PATH_TYPE_INVALID")
    return path

def metadata_facts(root: Path) -> dict:
    checked_path(root, directory=True)
    path = checked_path(root / ".runner")
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise ProbeError("RUNNER_METADATA_TOO_LARGE")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise ProbeError("RUNNER_METADATA_TOO_LARGE")
        data = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError):
        raise ProbeError("RUNNER_METADATA_INVALID") from None
    if not isinstance(data, dict):
        raise ProbeError("RUNNER_METADATA_INVALID")
    urls = [data[key] for key in ("repoUrl", "gitHubUrl") if key in data]
    if not urls or any(not isinstance(url, str) or url.rstrip("/") != EXPECTED_REPOSITORY_URL for url in urls):
        raise ProbeError("REQSYS_RUNNER_REPOSITORY_MISMATCH")
    name = data.get("agentName", data.get("runnerName", ""))
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,128}", name):
        raise ProbeError("RUNNER_NAME_INVALID")
    checked_path(root / "run.cmd")
    checked_path(root / "bin", directory=True)
    checked_path(root / "bin" / "Runner.Listener.exe")
    return {"registration_metadata_present": True, "repository_matches_reqsys": True,
            "runner_name": name, "registered_runtime_files_present": True}

def public_file_version(executable: Path) -> str | None:
    # Read Windows version resources; never start the runner executable.
    checked_path(executable)
    if os.name != "nt":
        return None
    try:
        version = ctypes.WinDLL("version", use_last_error=True)
        version.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32)]
        version.GetFileVersionInfoSizeW.restype = ctypes.c_uint32
        version.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        version.GetFileVersionInfoW.restype = ctypes.c_int
        version.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
        version.VerQueryValueW.restype = ctypes.c_int
        ignored = ctypes.c_uint32()
        size = version.GetFileVersionInfoSizeW(str(executable), ctypes.byref(ignored))
        if not 52 <= size <= 1048576:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(executable), 0, size, buffer):
            return None
        pointer, length = ctypes.c_void_p(), ctypes.c_uint32()
        if not version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)) or length.value < 52:
            return None
        words = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))
        if words[0] != 0xFEEF04BD:
            return None
        major_minor, build_revision = words[2], words[3]
        return ".".join(str(value) for value in (major_minor >> 16, major_minor & 65535,
                                                 build_revision >> 16, build_revision & 65535))
    except (AttributeError, OSError, ValueError):
        return None

def collect() -> dict:
    if (os.name != "nt" or socket.gethostname().casefold() != HOST.casefold()
            or os.environ.get("GITHUB_REPOSITORY") != CALLER_REPOSITORY
            or os.environ.get("RUNNER_NAME") != "DESKTOP-PDQK954-runtime"):
        raise ProbeError("FIXED_HOST_OR_CALLER_MISMATCH")
    local = os.environ.get("LOCALAPPDATA", "")
    if not local or not Path(local).is_absolute():
        raise ProbeError("LOCALAPPDATA_UNAVAILABLE")
    root = Path(local) / "ReqSys" / "Pc24x7GitHubRunner"
    facts = metadata_facts(root)
    facts["runner_file_version"] = public_file_version(root / "bin" / "Runner.Listener.exe")
    facts.update({"schema_version": 1, "host": HOST, "status": "metadata_verified",
                  "source_sha": os.environ.get("GITHUB_SHA", ""),
                  "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "github_connectivity_verified": False, "job_pickup_verified": False,
                  "local_listener_verified": False, "listener_probe": "not_performed",
                  "secrets_read": False, "credentials_read": False,
                  "runner_started": False, "registration_changed": False})
    return facts

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-file", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = collect()
        exit_code = 0
    except ProbeError as exc:
        evidence = {"schema_version": 1, "host": HOST, "status": "blocked",
                    "code": str(exc), "repository_matches_reqsys": False,
                    "github_connectivity_verified": False, "job_pickup_verified": False,
                    "secrets_read": False, "credentials_read": False,
                    "runner_started": False, "registration_changed": False}
        exit_code = 2
    args.evidence_file.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_file.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
