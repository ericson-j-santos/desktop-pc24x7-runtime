#!/usr/bin/env python3
"""RP23OGS/DEV only: stage one pinned official Tailscale MSI without installing.

Risk2, only inside a governed, exclusive worktree: one HTTPS origin, fixed
version/architecture, no redirects, no shell/admin, atomic no-overwrite, and
readback. Never signs in, changes services, executes MSI, or approves UAC.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import ssl
import stat
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

try:
    from scripts import rp23ogs_tailscale_admission as admission
    from scripts import rp23ogs_tailscale_windows_evidence as evidence
except ModuleNotFoundError:
    import rp23ogs_tailscale_admission as admission
    import rp23ogs_tailscale_windows_evidence as evidence

CONTRACT = "pass001-tailscale-official-msi-stage-v1"
CHUNK_BYTES = 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 30


class StageBlocked(ValueError):
    pass


def _require_exact_host() -> None:
    request = admission.fixed_request(
        "pass001-rp23ogs-msi-staging-20261121",
        "PASS-001:RP23OGS:tailscale:1.104.7",
    )
    admission.validate_request(request, actual_host=socket.gethostname(),
        system=platform.system(), machine=platform.machine())


def _open_official_msi():
    opener = urllib.request.build_opener(evidence._NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    req = urllib.request.Request(admission.OFFICIAL_ORIGIN,
        headers={"Accept": "application/octet-stream", "Accept-Encoding": "identity",
                 "User-Agent": "PASS001-Governed-MSI-Stage/1"}, method="GET")
    try:
        reply = opener.open(req, timeout=DOWNLOAD_TIMEOUT_SECONDS)
    except (OSError, urllib.error.URLError, ValueError):
        raise StageBlocked("OFFICIAL_PACKAGE_UNAVAILABLE") from None
    if reply.getcode() != 200 or reply.geturl() != admission.OFFICIAL_ORIGIN:
        reply.close()
        raise StageBlocked("OFFICIAL_PACKAGE_ORIGIN_MISMATCH")
    return reply


def stage_once(*, worktree: Path, response_factory=_open_official_msi) -> dict[str, object]:
    _require_exact_host()
    if worktree != Path.cwd() or not worktree.is_absolute():
        raise StageBlocked("WORKTREE_IDENTITY_MISMATCH")
    admission._no_links(worktree)
    stage_dir = worktree / "tailscale-pass001-staging"
    target = stage_dir / admission.MSI_NAME
    admission._no_links(stage_dir)
    if stage_dir.exists() and not stage_dir.is_dir():
        raise StageBlocked("STAGING_INVALID")
    official_record = evidence.get_official_digest()
    expected = admission.parse_official_digest(official_record)
    if expected != admission.SECONDARY_SHA256:
        raise StageBlocked("OFFICIAL_DIGEST_CONFLICT")

    if target.exists() or target.is_symlink():
        observed = admission.read_staged_msi(target, stage_dir)
        if observed != expected:
            raise StageBlocked("EXISTING_PACKAGE_DIGEST_MISMATCH")
        return {"contract": CONTRACT, "result": "ALREADY_STAGED_VERIFIED",
                "host": admission.HOST, "sha256": expected,
                "msi_staged": True, "idempotent_replay": True,
                "signature_verified": False, "install_authorized": False,
                "rollback_tested": False, "installation_executed": False,
                "privilege_elevation_authorized": False}

    if not stage_dir.exists():
        stage_dir.mkdir(mode=0o700)
    admission._no_links(stage_dir)
    # Create exclusively in this fresh, owned directory; never overwrite a
    # pre-existing MSI, do not stage under a shared system or user directory.
    fd, temporary_name = tempfile.mkstemp(prefix=".pass001-msi-", suffix=".part", dir=stage_dir)
    temporary = Path(temporary_name)
    published = False
    try:
        with os.fdopen(fd, "wb") as dest:
            written = 0
            digest = hashlib.sha256()
            with response_factory() as source:
                while True:
                    block = source.read(CHUNK_BYTES)
                    if not block:
                        break
                    written += len(block)
                    if written > admission.MAX_MSI_BYTES:
                        raise StageBlocked("PACKAGE_SIZE_INVALID")
                    digest.update(block)
                    dest.write(block)
            dest.flush()
            os.fsync(dest.fileno())
        if written < 1_000_000:
            raise StageBlocked("PACKAGE_SIZE_INVALID")
        if digest.hexdigest() != expected:
            raise StageBlocked("PACKAGE_HASH_MISMATCH")
        if target.exists() or target.is_symlink():
            raise StageBlocked("PACKAGE_APPEARED_CONCURRENTLY")
        # Link creation is atomic and refuses an existing target on NTFS;
        # unlike os.replace it cannot overwrite another worker's package.
        os.link(temporary, target)
        published = True
        if admission.read_staged_msi(target, stage_dir) != expected:
            raise StageBlocked("PACKAGE_POST_PUBLISH_MISMATCH")
    finally:
        try:
            temporary.unlink(missing_ok=True)  # This worker's own temporary file only.
        except OSError:
            pass
    if not published:
        raise StageBlocked("STAGING_NOT_PUBLISHED")
    return {"contract": CONTRACT, "result": "STAGED_VERIFIED_INSTALL_BLOCKED",
            "host": admission.HOST, "sha256": expected,
            "msi_staged": True, "idempotent_replay": False,
            "signature_verified": False, "install_authorized": False,
            "rollback_tested": False, "installation_executed": False,
            "privilege_elevation_authorized": False}


def main(argv: list[str] | None = None) -> int:
    import sys
    params = sys.argv[1:] if argv is None else argv
    try:
        if params:
            raise StageBlocked("ARGUMENTS_DENIED")
        result = stage_once(worktree=Path.cwd())
    except (StageBlocked, admission.AdmissionBlocked, evidence.EvidenceBlocked, OSError) as exc:
        reason = "STAGING_IO_UNAVAILABLE" if isinstance(exc, OSError) else str(exc)
        print(json.dumps({"contract": CONTRACT, "result": "BLOCKED", "reason": reason,
                          "installation_executed": False, "privilege_elevation_authorized": False},
                         sort_keys=True))
        return 20
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
