#!/usr/bin/env python3
"""PASS-001 / Runtime #147: read-only, native Windows evidence for a pinned Tailscale MSI.

No installer, privilege elevation, service mutation, account login, activation,
MSI download, PowerShell, or shell execution. Requires an independently staged
MSI and the actual checksum from Tailscale's fixed HTTPS origin. Rollback is
only a *plan* until a separately authorized installation/restoration test.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    from scripts import rp23ogs_tailscale_admission as admission
except ModuleNotFoundError:  # Executed as `python -B scripts/<filename>.py` via Gateway.
    import rp23ogs_tailscale_admission as admission

CONTRACT = "pass001-tailscale-windows-evidence-readonly-v1"
EXPECTED_PUBLISHER = "Tailscale Inc."
CHECKSUM_MAX_BYTES = 300
CHECKSUM_TIMEOUT_SECONDS = 12


class EvidenceBlocked(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_official_digest(*, opener=None) -> bytes:
    """Fetch only a bounded SHA-256 record through TLS, never a binary installer."""
    if opener is None:
        opener = urllib.request.build_opener(_NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(
        admission.OFFICIAL_DIGEST_URL,
        headers={"Accept": "text/plain", "User-Agent": "PASS001-ReadOnly-MSI-Preflight/1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=CHECKSUM_TIMEOUT_SECONDS) as response:
            if response.getcode() != 200 or response.geturl() != admission.OFFICIAL_DIGEST_URL:
                raise EvidenceBlocked("OFFICIAL_DIGEST_ORIGIN_MISMATCH")
            body = response.read(CHECKSUM_MAX_BYTES + 1)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        if isinstance(exc, EvidenceBlocked):
            raise
        raise EvidenceBlocked("OFFICIAL_DIGEST_UNAVAILABLE") from None
    if not body or len(body) > CHECKSUM_MAX_BYTES:
        raise EvidenceBlocked("OFFICIAL_DIGEST_SIZE_INVALID")
    digest = admission.parse_official_digest(body)
    if digest != admission.SECONDARY_SHA256:
        raise EvidenceBlocked("DIGEST_SOURCES_DISAGREE")
    return body


# These structures model only the *leading fields* needed to read the trusted
# signer certificate from WinVerifyTrust provider state. No writes or shell.
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]


class _FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_uint32), ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", ctypes.c_void_p), ("pgKnownSubject", ctypes.c_void_p)]


class _TRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_uint32),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_uint32),
        ("fdwRevocationChecks", ctypes.c_uint32),
        ("dwUnionChoice", ctypes.c_uint32),
        ("pFile", ctypes.c_void_p),
        ("dwStateAction", ctypes.c_uint32),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_uint32),
        ("dwUIContext", ctypes.c_uint32),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class _PROVIDER_CERT_PREFIX(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_uint32), ("pCert", ctypes.c_void_p)]


class _PROVIDER_SIGNER_PREFIX(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_uint32), ("sftVerifyAsOf", _FILETIME),
                ("csCertChain", ctypes.c_uint32),
                ("pasCertChain", ctypes.POINTER(_PROVIDER_CERT_PREFIX))]


def verify_windows_authenticode(path: Path) -> bool:
    """Windows WinVerifyTrust with chain revocation + exact signer CN check.

    Always fail closed if Windows cannot obtain the chain, signer or publisher.
    No automatic trust-store changes; no PowerShell/signtool subprocess.
    """
    if os.name != "nt" or platform.system() != "Windows":
        raise EvidenceBlocked("WINDOWS_SIGNATURE_HOST_REQUIRED")
    admission._no_links(path)
    if not path.is_file() or path.name != admission.MSI_NAME:
        raise EvidenceBlocked("SIGNATURE_TARGET_INVALID")

    try:
        wt = ctypes.WinDLL("wintrust", use_last_error=True)
        cr = ctypes.WinDLL("crypt32", use_last_error=True)
        fn = wt.WinVerifyTrust
        fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.POINTER(_TRUST_DATA)]
        fn.restype = ctypes.c_int32
        provider = wt.WTHelperProvDataFromStateData
        provider.argtypes = [ctypes.c_void_p]
        provider.restype = ctypes.c_void_p
        signer = wt.WTHelperGetProvSignerFromChain
        signer.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        signer.restype = ctypes.c_void_p
        name_fn = cr.CertGetNameStringW
        name_fn.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
        name_fn.restype = ctypes.c_uint32
    except (AttributeError, OSError) as exc:
        raise EvidenceBlocked("WINDOWS_TRUST_PROVIDER_UNAVAILABLE") from None

    action = _GUID(0x00AAC56B, 0xCD44, 0x11D0,
                   (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    file_info = _FILE_INFO(ctypes.sizeof(_FILE_INFO), str(path.resolve(strict=True)), None, None)
    trust = _TRUST_DATA()
    trust.cbStruct = ctypes.sizeof(_TRUST_DATA)
    trust.dwUIChoice = 2                 # WTD_UI_NONE
    trust.fdwRevocationChecks = 1       # WTD_REVOKE_WHOLECHAIN
    trust.dwUnionChoice = 1            # WTD_CHOICE_FILE
    trust.pFile = ctypes.addressof(file_info)
    trust.dwStateAction = 1            # WTD_STATEACTION_VERIFY
    trust.dwProvFlags = 0x80           # WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
    passed = False
    try:
        if fn(None, ctypes.byref(action), ctypes.byref(trust)) != 0:
            raise EvidenceBlocked("WINDOWS_AUTHENTICODE_INVALID")
        data_ptr = provider(trust.hWVTStateData)
        if not data_ptr:
            raise EvidenceBlocked("WINDOWS_SIGNER_UNAVAILABLE")
        signer_ptr = signer(data_ptr, 0, 0, 0)
        if not signer_ptr:
            raise EvidenceBlocked("WINDOWS_SIGNER_UNAVAILABLE")
        chain = ctypes.cast(signer_ptr, ctypes.POINTER(_PROVIDER_SIGNER_PREFIX)).contents
        if not 1 <= chain.csCertChain <= 20 or not chain.pasCertChain:
            raise EvidenceBlocked("WINDOWS_CERT_CHAIN_INVALID")
        cert_context = chain.pasCertChain[0].pCert
        if not cert_context:
            raise EvidenceBlocked("WINDOWS_CERT_CHAIN_INVALID")
        buf = ctypes.create_unicode_buffer(256)
        n = name_fn(cert_context, 4, 0, None, buf, len(buf))  # CERT_NAME_SIMPLE_DISPLAY_TYPE
        if n < 2 or n > len(buf) or buf.value != EXPECTED_PUBLISHER:
            raise EvidenceBlocked("WINDOWS_PUBLISHER_MISMATCH")
        passed = True
    finally:
        if trust.hWVTStateData:
            trust.dwStateAction = 2    # WTD_STATEACTION_CLOSE
            if fn(None, ctypes.byref(action), ctypes.byref(trust)) != 0:
                passed = False
    if not passed:
        raise EvidenceBlocked("WINDOWS_TRUST_STATE_CLOSE_FAILED")
    return True


def rollback_plan(*, package: Path, verified_digest: str) -> dict[str, object]:
    """Only attest that a verified MSI can be retained for a future uninstall.

    Nothing here uninstalls Tailscale or claims an installed-state backup.
    """
    if package.name != admission.MSI_NAME:
        raise EvidenceBlocked("ROLLBACK_SOURCE_MISMATCH")
    if admission.read_staged_msi(package, package.parent) != verified_digest:
        raise EvidenceBlocked("ROLLBACK_SOURCE_CHANGED")
    return {
        "rollback_method": "WINDOWS_INSTALLER_REMOVE_USING_SAME_VERIFIED_MSI",
        "rollback_source_sha256": verified_digest,
        "rollback_source_readback": True,
        "rollback_plan_checked": True,
        "installed_state_backup_verified": False,
        "rollback_tested": False,
        "install_authorized_by_gate": False,
    }


def collect_evidence(*, stage_root: Path, correlation_id: str, idempotency_key: str) -> dict[str, object]:
    req = admission.fixed_request(correlation_id, idempotency_key)
    admission.validate_request(req, actual_host=socket.gethostname(),
                               system=platform.system(), machine=platform.machine())
    if stage_root != Path.cwd() / "tailscale-pass001-staging":
        raise EvidenceBlocked("STAGE_ROOT_NOT_WORKTREE_LOCAL")
    package = stage_root / admission.MSI_NAME
    # First read the local file, before any network call or WinTrust operation.
    # The official digest remains mandatory and is fetched from only the pinned URL.
    admission.read_staged_msi(package, stage_root)
    official_record = get_official_digest()
    verified = admission.qualify(req, stage_root=stage_root,
        official_digest_bytes=official_record, signature_attestation=verify_windows_authenticode)
    plan = rollback_plan(package=package, verified_digest=str(verified["package_sha256"]))
    return {**verified, **plan, "evidence_contract": CONTRACT,
            "official_digest_origin": admission.OFFICIAL_DIGEST_URL,
            "windows_publisher": EXPECTED_PUBLISHER,
            "installation_executed": False, "privilege_elevation_authorized": False,
            "independent_validator_passed": False}


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if arguments not in ([], ["--checksum-only"]):
            raise EvidenceBlocked("ARGUMENTS_DENIED")
        if arguments == ["--checksum-only"]:
            request = admission.fixed_request(
                "pass001-rp23ogs-windows-evidence-20261121",
                "PASS-001:RP23OGS:tailscale:1.104.7",
            )
            admission.validate_request(request, actual_host=socket.gethostname(),
                                       system=platform.system(), machine=platform.machine())
            official = admission.parse_official_digest(get_official_digest())
            result = {
                "contract": CONTRACT, "result": "OFFICIAL_DIGEST_ATTESTED_INSTALL_BLOCKED",
                "host": admission.HOST, "official_sha256": official,
                "official_digest_origin": admission.OFFICIAL_DIGEST_URL,
                "msi_staged": False, "signature_verified": False,
                "rollback_tested": False, "installation_executed": False,
                "install_authorized_by_gate": False,
                "privilege_elevation_authorized": False,
            }
        else:
            result = collect_evidence(stage_root=Path.cwd() / "tailscale-pass001-staging",
                correlation_id="pass001-rp23ogs-windows-evidence-20261121",
                idempotency_key="PASS-001:RP23OGS:tailscale:1.104.7")
    except (EvidenceBlocked, admission.AdmissionBlocked) as exc:
        print(json.dumps({"contract": CONTRACT, "result": "BLOCKED", "reason": str(exc),
                          "host_target": admission.HOST, "installation_executed": False,
                          "privilege_elevation_authorized": False}, sort_keys=True))
        return 20
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
