#!/usr/bin/env python3
"""PASS-001 / Runtime #147: preflight fail-closed for a future native Tailscale MSI install.

NO download, installation, account sign-in, Windows service changes, elevation,
network activation, or invocation of msiexec is implemented by this module.
This candidate must be integrated into the existing governed Runtime Platform,
not executed as a bypass of the Command Gateway.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

HOST = "DESKTOP-RP23OGS"
ENV = "DEV"
CONTRACT = "pass001-tailscale-msi-readonly-preflight-v1"
RULES_SHA = "58dcd4200f412a866278027ba9e433439a03f3b3"
VERSION = "1.104.7"
MSI_NAME = f"tailscale-setup-{VERSION}-amd64.msi"
OFFICIAL_ORIGIN = f"https://pkgs.tailscale.com/stable/{MSI_NAME}"
OFFICIAL_DIGEST_URL = OFFICIAL_ORIGIN + ".sha256"
# SECONDARY corroboration ONLY (Chocolatey v1.104.7); NOT an official attestation.
SECONDARY_SHA256 = "676b5b32fdd1aeaee90d8e8f38e222635b216fbdfbf877bf01cb1d7cda330ec5"
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
MAX_MSI_BYTES = 120 * 1024 * 1024


class AdmissionBlocked(ValueError):
    """Reason codes never include filenames from callers or private system data."""


@dataclass(frozen=True)
class Request:
    contract: str
    host: str
    environment: str
    version: str
    rules_sha: str
    correlation_id: str
    idempotency_key: str
    # The caller cannot authorize UAC, deployment, sign-in, or VPN activation.


def fixed_request(correlation_id: str, idempotency_key: str) -> Request:
    return Request(CONTRACT, HOST, ENV, VERSION, RULES_SHA, correlation_id, idempotency_key)


def validate_request(request: Request, *, actual_host: str, system: str, machine: str) -> None:
    if type(request) is not Request or (
        request.contract != CONTRACT or request.host != HOST
        or request.environment != ENV or request.version != VERSION
        or request.rules_sha != RULES_SHA
    ):
        raise AdmissionBlocked("REQUEST_SCOPE_MISMATCH")
    if (not re.fullmatch(r"[A-Za-z0-9._:-]{12,128}", request.correlation_id)
        or not re.fullmatch(r"[A-Za-z0-9._:-]{12,160}", request.idempotency_key)):
        raise AdmissionBlocked("REQUEST_ID_INVALID")
    if (actual_host.upper() != HOST or system != "Windows" or machine.upper() not in {"AMD64", "X86_64"}):
        raise AdmissionBlocked("PHYSICAL_HOST_MISMATCH")


def _no_links(path: Path) -> None:
    for current in (path, *path.parents):
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            raise AdmissionBlocked("REPARSE_POINT_DENIED")


def read_staged_msi(path: Path, stage_root: Path) -> str:
    """Read only a fixed-size regular file under a nonredirected, fixed staging root."""
    if path.name != MSI_NAME or path.parent != stage_root:
        raise AdmissionBlocked("PACKAGE_PATH_DENIED")
    _no_links(path)
    _no_links(stage_root)
    if not stage_root.is_dir() or not path.is_file():
        raise AdmissionBlocked("PACKAGE_NOT_STAGED")
    try:
        if path.resolve(strict=True).parent != stage_root.resolve(strict=True):
            raise AdmissionBlocked("PACKAGE_PATH_DENIED")
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or not 1_000_000 <= before.st_size <= MAX_MSI_BYTES:
            raise AdmissionBlocked("PACKAGE_SIZE_INVALID")
        h = hashlib.sha256()
        with path.open("rb") as f:
            while block := f.read(1024 * 1024):
                h.update(block)
        after = path.stat()
        if (before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ino != after.st_ino):
            raise AdmissionBlocked("PACKAGE_CHANGED_DURING_READ")
        return h.hexdigest()
    except (OSError, ValueError) as exc:
        if isinstance(exc, AdmissionBlocked):
            raise
        raise AdmissionBlocked("PACKAGE_READ_UNAVAILABLE") from None


def parse_official_digest(raw: bytes) -> str:
    """Accept only a Tailscale .sha256 record for our exact file; no arbitrary URLs."""
    if type(raw) is not bytes or len(raw) > 300:
        raise AdmissionBlocked("OFFICIAL_DIGEST_INVALID")
    try:
        decoded = raw.decode("ascii").strip()
        if "\r" in decoded or "\n" in decoded:
            raise AdmissionBlocked("OFFICIAL_DIGEST_INVALID")
        tokens = decoded.split()
    except UnicodeError:
        raise AdmissionBlocked("OFFICIAL_DIGEST_INVALID") from None
    if len(tokens) not in (1, 2) or not DIGEST.fullmatch(tokens[0].lower()):
        raise AdmissionBlocked("OFFICIAL_DIGEST_INVALID")
    if len(tokens) == 2 and tokens[1].lstrip("*") != MSI_NAME:
        raise AdmissionBlocked("OFFICIAL_DIGEST_WRONG_FILE")
    return tokens[0].lower()


def qualify(
    request: Request,
    *,
    stage_root: Path,
    official_digest_bytes: bytes | None,
    signature_attestation: Callable[[Path], bool] | None,
    actual_host: str | None = None,
    system: str | None = None,
    machine: str | None = None,
) -> dict[str, object]:
    """No network or subprocesses. Attestation must be performed separately on Windows."""
    validate_request(request, actual_host=actual_host or socket.gethostname(),
                     system=system or platform.system(), machine=machine or platform.machine())
    if stage_root.name != "tailscale-pass001-staging" or not stage_root.is_absolute():
        raise AdmissionBlocked("STAGE_ROOT_DENIED")
    # No official .sha256 fetch available in this sandbox: fail closed.
    if official_digest_bytes is None:
        raise AdmissionBlocked("OFFICIAL_SHA256_ATTESTATION_REQUIRED")
    official = parse_official_digest(official_digest_bytes)
    if official != SECONDARY_SHA256:
        raise AdmissionBlocked("DIGEST_SOURCES_DISAGREE")
    msi_path = stage_root / MSI_NAME
    if read_staged_msi(msi_path, stage_root) != official:
        raise AdmissionBlocked("PACKAGE_HASH_MISMATCH")
    # NEVER substitute a user-provided boolean for a validated Windows
    # Authenticode publisher + chain attestation from a trusted runtime adapter.
    if signature_attestation is None or signature_attestation(msi_path) is not True:
        raise AdmissionBlocked("WINDOWS_SIGNATURE_NOT_ATTESTED")
    return {
        "contract": CONTRACT,
        "result": "PACKAGE_PRECHECK_PASSED_INSTALL_STILL_BLOCKED",
        "host": HOST, "environment": ENV, "version": VERSION,
        "package_sha256": official,
        "rules_sha": RULES_SHA,
        "correlation_id": request.correlation_id,
        "idempotency_key": request.idempotency_key,
        "backup_verified": False,
        "rollback_tested": False,
        "independent_validator_passed": False,
        "privilege_elevation_authorized": False,
        "installation_authorized_by_gate": False,
        "installation_executed": False,
        "login_authorized": False,
        "tailnet_activation_authorized": False,
        "serve_or_funnel_authorized": False,
    }


def main() -> int:
    # Read-only current-host/scope diagnostic. No external attestations are
    # accepted from a caller, so this CLI CANNOT silently authorize installation.
    request = fixed_request("pass001-rp23ogs-msi-qualify-20261121", "PASS-001:RP23OGS:tailscale:1.104.7")
    try:
        result = qualify(request,
                         stage_root=Path.cwd() / "tailscale-pass001-staging",
                         official_digest_bytes=None, signature_attestation=None)
    except AdmissionBlocked as exc:
        result = {"contract": CONTRACT, "result": "BLOCKED", "reason": str(exc),
                  "host_target": HOST, "installation_executed": False,
                  "privilege_elevation_authorized": False}
        print(json.dumps(result, sort_keys=True))
        return 20
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
