#!/usr/bin/env python3
"""Protected S3 credentials for the Desktop Worker Pool runtime.

Provisioning accepts credential material only from stdin.  At rest, the exact
validated credential envelope is protected with Windows CurrentUser DPAPI and a
protected DACL.  Runtime callers receive an already constructed S3 client, not
credential strings or process-global ``AWS_*`` variables.

This module deliberately does not create cloud credentials, install a service,
or claim that the Scheduled Task S4U identity has been validated.  Those are
physical-host gates.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
from typing import Any, BinaryIO, TypeVar
from urllib.parse import urlsplit


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from desktop_orchestrator_protected_state import dpapi  # noqa: E402
from register_reqsys_dev_owner_actions import (  # noqa: E402
    OperationError as PrivateFileError,
    WindowsPrivateFiles,
    no_reparse,
)


__all__ = ("S3Route", "credential_status", "run_with_s3_client")


EXPECTED_HOST = "DESKTOP-PDQK954"
CONTRACT = "desktop-worker-s3-credential-v1"
SCHEMA_VERSION = "1.0.0"
INSTALL_CONFIRM = "INSTALL-DESKTOP-WORKER-S3-CREDENTIAL-V1"
MAX_INPUT_BYTES = 16 * 1024
MAX_PROTECTED_FILE_BYTES = 64 * 1024
ACCESS_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+=/@:-]{2,511}\Z")
BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
REGION_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\Z")
SAFE_REASONS = {
    "fixed_windows_host_required",
    "localappdata_unavailable",
    "credential_path_inside_repository",
    "credential_path_invalid",
    "credential_already_installed",
    "credential_not_installed",
    "credential_stdin_pipe_required",
    "credential_confirmation_invalid",
    "credential_input_invalid",
    "credential_envelope_invalid",
    "credential_cipher_invalid",
    "credential_protection_failed",
    "credential_acl_failed",
    "credential_write_failed",
    "credential_read_failed",
    "credential_readback_failed",
    "s3_route_invalid",
    "s3_dependency_missing",
    "s3_client_creation_failed",
    "s3_callback_failed",
}


class CredentialBootstrapError(RuntimeError):
    """Closed-set operational failure that never contains credential material."""

    def __init__(self, code: str):
        self.code = code if code in SAFE_REASONS else "credential_operation_failed"
        super().__init__(self.code)


@dataclass(frozen=True, repr=False)
class S3Credential:
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None

    def __repr__(self) -> str:
        return "S3Credential(<redacted>)"


@dataclass(frozen=True)
class S3Route:
    bucket: str
    region: str
    endpoint_url: str
    key_prefix: str

    def __post_init__(self) -> None:
        if (
            not BUCKET_RE.fullmatch(self.bucket)
            or ".." in self.bucket
            or ".-" in self.bucket
            or "-." in self.bucket
        ):
            raise CredentialBootstrapError("s3_route_invalid")
        if not REGION_RE.fullmatch(self.region):
            raise CredentialBootstrapError("s3_route_invalid")
        if (
            not PREFIX_RE.fullmatch(self.key_prefix)
            or self.key_prefix.endswith("/")
            or any(part in {"", ".", ".."} for part in self.key_prefix.split("/"))
        ):
            raise CredentialBootstrapError("s3_route_invalid")
        try:
            endpoint = urlsplit(self.endpoint_url)
        except ValueError:
            raise CredentialBootstrapError("s3_route_invalid") from None
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.query
            or endpoint.fragment
            or endpoint.path not in {"", "/"}
        ):
            raise CredentialBootstrapError("s3_route_invalid")


T = TypeVar("T")


def require_windows_host() -> None:
    if os.name != "nt" or socket.gethostname().casefold() != EXPECTED_HOST.casefold():
        raise CredentialBootstrapError("fixed_windows_host_required")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise CredentialBootstrapError("credential_envelope_invalid")
        result[key] = value
    return result


def _load_json(raw: bytes, *, reason: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CredentialBootstrapError(reason) from None
    except CredentialBootstrapError:
        raise CredentialBootstrapError(reason) from None
    if type(value) is not dict:
        raise CredentialBootstrapError(reason)
    return value


def _printable_secret(value: object, *, minimum: int) -> bool:
    return (
        type(value) is str
        and minimum <= len(value) <= 4096
        and all(33 <= ord(character) <= 126 for character in value)
    )


def _credential_from_value(value: Mapping[str, Any]) -> S3Credential:
    required = {
        "schema_version",
        "aws_access_key_id",
        "aws_secret_access_key",
    }
    optional = {"aws_session_token"}
    if not required.issubset(value) or not set(value).issubset(required | optional):
        raise CredentialBootstrapError("credential_input_invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise CredentialBootstrapError("credential_input_invalid")
    access_key = value.get("aws_access_key_id")
    secret_key = value.get("aws_secret_access_key")
    session_token = value.get("aws_session_token")
    if type(access_key) is not str or not ACCESS_KEY_RE.fullmatch(access_key):
        raise CredentialBootstrapError("credential_input_invalid")
    if not _printable_secret(secret_key, minimum=8):
        raise CredentialBootstrapError("credential_input_invalid")
    if session_token is not None and not _printable_secret(session_token, minimum=8):
        raise CredentialBootstrapError("credential_input_invalid")
    return S3Credential(access_key, secret_key, session_token)


def _credential_bytes(credential: S3Credential) -> bytes:
    value: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "aws_access_key_id": credential.access_key_id,
        "aws_secret_access_key": credential.secret_access_key,
    }
    if credential.session_token is not None:
        value["aws_session_token"] = credential.session_token
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def read_credential_stdin(stream: BinaryIO) -> S3Credential:
    isatty = getattr(stream, "isatty", None)
    if callable(isatty) and isatty():
        raise CredentialBootstrapError("credential_stdin_pipe_required")
    raw = bytearray(stream.read(MAX_INPUT_BYTES + 1))
    try:
        if not raw or len(raw) > MAX_INPUT_BYTES:
            raise CredentialBootstrapError("credential_input_invalid")
        value = _load_json(bytes(raw), reason="credential_input_invalid")
        return _credential_from_value(value)
    finally:
        for index in range(len(raw)):
            raw[index] = 0


def default_credential_path(environ: Mapping[str, str] | None = None) -> Path:
    values = os.environ if environ is None else environ
    base = values.get("LOCALAPPDATA", "")
    if not base or not Path(base).is_absolute():
        raise CredentialBootstrapError("localappdata_unavailable")
    return (
        Path(base)
        / "ReqSys"
        / "EngineeringWorkerPool"
        / "protected-credentials"
        / "s3-credential-v1.json"
    )


def _validate_destination(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=False)
        repository = REPOSITORY_ROOT.resolve(strict=True)
    except OSError:
        raise CredentialBootstrapError("credential_path_invalid") from None
    if resolved == repository or repository in resolved.parents:
        raise CredentialBootstrapError("credential_path_inside_repository")
    if not resolved.name or resolved.name != "s3-credential-v1.json":
        raise CredentialBootstrapError("credential_path_invalid")
    return resolved


def _outer_envelope(ciphertext: bytes) -> bytes:
    value = {
        "schema_version": SCHEMA_VERSION,
        "contract": CONTRACT,
        "protection": {
            "provider": "windows-dpapi",
            "scope": "current-user",
            "ui_forbidden": True,
        },
        "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
    }
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _ciphertext_from_outer(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_PROTECTED_FILE_BYTES:
        raise CredentialBootstrapError("credential_envelope_invalid")
    value = _load_json(raw, reason="credential_envelope_invalid")
    if set(value) != {
        "schema_version",
        "contract",
        "protection",
        "ciphertext_base64",
        "ciphertext_sha256",
    }:
        raise CredentialBootstrapError("credential_envelope_invalid")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("contract") != CONTRACT:
        raise CredentialBootstrapError("credential_envelope_invalid")
    if value.get("protection") != {
        "provider": "windows-dpapi",
        "scope": "current-user",
        "ui_forbidden": True,
    }:
        raise CredentialBootstrapError("credential_envelope_invalid")
    encoded = value.get("ciphertext_base64")
    digest = value.get("ciphertext_sha256")
    if type(encoded) is not str or type(digest) is not str or not re.fullmatch(
        r"[0-9a-f]{64}", digest,
    ):
        raise CredentialBootstrapError("credential_envelope_invalid")
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise CredentialBootstrapError("credential_cipher_invalid") from None
    if not ciphertext or len(ciphertext) > MAX_INPUT_BYTES + 8192:
        raise CredentialBootstrapError("credential_cipher_invalid")
    if not secrets.compare_digest(hashlib.sha256(ciphertext).hexdigest(), digest):
        raise CredentialBootstrapError("credential_cipher_invalid")
    return ciphertext


def _read_protected_bytes(path: Path) -> bytes:
    try:
        no_reparse(path)
        stat_result = path.stat()
        if not path.is_file() or stat_result.st_nlink != 1:
            raise CredentialBootstrapError("credential_path_invalid")
        if stat_result.st_size <= 0 or stat_result.st_size > MAX_PROTECTED_FILE_BYTES:
            raise CredentialBootstrapError("credential_envelope_invalid")
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROTECTED_FILE_BYTES + 1)
    except CredentialBootstrapError:
        raise
    except (OSError, PrivateFileError):
        raise CredentialBootstrapError("credential_read_failed") from None
    if len(raw) > MAX_PROTECTED_FILE_BYTES:
        raise CredentialBootstrapError("credential_envelope_invalid")
    return raw


def _unprotect_credential(
    raw: bytes,
    *,
    unprotect: Callable[[bytes], bytes],
) -> S3Credential:
    ciphertext = _ciphertext_from_outer(raw)
    try:
        decrypted = unprotect(ciphertext)
        if type(decrypted) is not bytes or not decrypted:
            raise CredentialBootstrapError("credential_protection_failed")
        plaintext = bytearray(decrypted)
    except CredentialBootstrapError:
        raise
    except Exception:
        raise CredentialBootstrapError("credential_protection_failed") from None
    try:
        value = _load_json(bytes(plaintext), reason="credential_input_invalid")
        credential = _credential_from_value(value)
        if not secrets.compare_digest(_credential_bytes(credential), bytes(plaintext)):
            raise CredentialBootstrapError("credential_envelope_invalid")
        return credential
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0


def _load_credential_core(
    path: Path,
    *,
    acl: Any,
    unprotect: Callable[[bytes], bytes],
) -> S3Credential:
    destination = _validate_destination(path)
    return _load_validated_file(destination, acl=acl, unprotect=unprotect)


def _load_validated_file(
    path: Path,
    *,
    acl: Any,
    unprotect: Callable[[bytes], bytes],
) -> S3Credential:
    if not path.exists() and not path.is_symlink():
        raise CredentialBootstrapError("credential_not_installed")
    try:
        no_reparse(path.parent)
        no_reparse(path)
        if not path.is_file():
            raise CredentialBootstrapError("credential_path_invalid")
        acl.check(path.parent)
        acl.check(path)
    except CredentialBootstrapError:
        raise
    except (OSError, PrivateFileError):
        raise CredentialBootstrapError("credential_acl_failed") from None
    return _unprotect_credential(_read_protected_bytes(path), unprotect=unprotect)


def _install_credential_core(
    credential: S3Credential,
    path: Path,
    *,
    acl: Any,
    protect: Callable[[bytes], bytes],
    unprotect: Callable[[bytes], bytes],
) -> dict[str, Any]:
    destination = _validate_destination(path)
    if destination.exists() or destination.is_symlink():
        raise CredentialBootstrapError("credential_already_installed")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        no_reparse(destination.parent)
        acl.secure(destination.parent)
    except (OSError, PrivateFileError):
        raise CredentialBootstrapError("credential_acl_failed") from None

    plaintext = bytearray(_credential_bytes(credential))
    pending = destination.with_name(
        f".{destination.name}.{secrets.token_hex(12)}.pending",
    )
    published = False
    committed_verified = False
    try:
        try:
            ciphertext = protect(bytes(plaintext))
            if (
                type(ciphertext) is not bytes
                or not ciphertext
                or len(ciphertext) > MAX_INPUT_BYTES + 8192
            ):
                raise CredentialBootstrapError("credential_protection_failed")
        except CredentialBootstrapError:
            raise
        except Exception:
            raise CredentialBootstrapError("credential_protection_failed") from None
        protected = _outer_envelope(ciphertext)
        try:
            descriptor = os.open(
                pending,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(protected)
                stream.flush()
                os.fsync(stream.fileno())
            acl.secure(pending)
        except (OSError, PrivateFileError):
            raise CredentialBootstrapError("credential_write_failed") from None

        staged = _load_validated_file(pending, acl=acl, unprotect=unprotect)
        if not secrets.compare_digest(_credential_bytes(staged), bytes(plaintext)):
            raise CredentialBootstrapError("credential_readback_failed")
        staged = None
        try:
            # On Windows, os.rename is atomic and refuses an existing target.
            # This closes the check/publish race without replacing credentials.
            os.rename(pending, destination)
            published = True
            acl.check(destination)
        except (OSError, PrivateFileError):
            raise CredentialBootstrapError("credential_write_failed") from None
        stored = _load_credential_core(destination, acl=acl, unprotect=unprotect)
        if not secrets.compare_digest(_credential_bytes(stored), bytes(plaintext)):
            raise CredentialBootstrapError("credential_readback_failed")
        stored = None
        committed_verified = True
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
        try:
            if pending.exists() or pending.is_symlink():
                pending.unlink()
        except OSError:
            pass
        if published and not committed_verified:
            try:
                destination.unlink()
            except OSError:
                pass

    return _safe_status("credential_installed")


def _protect_current_user(data: bytes) -> bytes:
    return dpapi(data, encrypt=True)


def _unprotect_current_user(data: bytes) -> bytes:
    return dpapi(data, encrypt=False)


def _install_credential(credential: S3Credential, path: Path | None = None) -> dict[str, Any]:
    require_windows_host()
    destination = default_credential_path() if path is None else path
    try:
        acl = WindowsPrivateFiles()
    except (OSError, PrivateFileError):
        raise CredentialBootstrapError("credential_acl_failed") from None
    return _install_credential_core(
        credential,
        destination,
        acl=acl,
        protect=_protect_current_user,
        unprotect=_unprotect_current_user,
    )


def _load_credential(path: Path | None = None) -> S3Credential:
    require_windows_host()
    destination = default_credential_path() if path is None else path
    try:
        acl = WindowsPrivateFiles()
    except (OSError, PrivateFileError):
        raise CredentialBootstrapError("credential_acl_failed") from None
    return _load_credential_core(
        destination,
        acl=acl,
        unprotect=_unprotect_current_user,
    )


def _default_client_factory(route: S3Route, credential: S3Credential) -> Any:
    try:
        import boto3  # type: ignore[import-not-found]
        from botocore.config import Config  # type: ignore[import-not-found]
    except ImportError:
        raise CredentialBootstrapError("s3_dependency_missing") from None
    arguments: dict[str, Any] = {
        "aws_access_key_id": credential.access_key_id,
        "aws_secret_access_key": credential.secret_access_key,
        "region_name": route.region,
        "endpoint_url": route.endpoint_url,
        "verify": True,
        "config": Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            retries={"mode": "standard", "total_max_attempts": 1},
            ignore_configured_endpoint_urls=True,
        ),
    }
    if credential.session_token is not None:
        arguments["aws_session_token"] = credential.session_token
    try:
        return boto3.client("s3", **arguments)
    except Exception:
        raise CredentialBootstrapError("s3_client_creation_failed") from None


def _run_with_s3_client_core(
    route: S3Route,
    callback: Callable[[Any, S3Route], T],
    *,
    credential_loader: Callable[[], S3Credential],
    client_factory: Callable[[S3Route, S3Credential], Any],
) -> T:
    credential: S3Credential | None = None
    client: Any = None
    try:
        credential = credential_loader()
        client = client_factory(route, credential)
        return callback(client, route)
    except CredentialBootstrapError:
        raise
    except Exception:
        raise CredentialBootstrapError("s3_callback_failed") from None
    finally:
        credential = None
        if client is not None:
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
        client = None


def run_with_s3_client(
    route: S3Route,
    callback: Callable[[Any, S3Route], T],
) -> T:
    """Invoke one explicit Python callback with a bounded, explicit S3 client."""

    require_windows_host()
    return _run_with_s3_client_core(
        route,
        callback,
        credential_loader=_load_credential,
        client_factory=_default_client_factory,
    )


def _safe_status(state: str) -> dict[str, Any]:
    return {
        "ok": True,
        "state": state,
        "contract": CONTRACT,
        "schema_version": SCHEMA_VERSION,
        "protection": "windows_dpapi_current_user",
        "ui_forbidden": True,
        "acl": "current_user_and_system_only",
        "credential_values_exposed": False,
        "plaintext_persisted": False,
        "process_global_aws_environment_mutated": False,
        "s4u_identity_physically_validated": False,
    }


def credential_status() -> dict[str, Any]:
    credential = _load_credential()
    credential = None
    return _safe_status("credential_verified_for_current_process_identity")


def _blocked_status(reason: str) -> dict[str, Any]:
    return {
        "ok": False,
        "state": "credential_operation_blocked",
        "reason": reason if reason in SAFE_REASONS else "credential_operation_failed",
        "contract": CONTRACT,
        "credential_values_exposed": False,
        "plaintext_persisted": False,
        "process_global_aws_environment_mutated": False,
        "s4u_identity_physically_validated": False,
    }


def main(
    argv: list[str] | None = None,
    *,
    stdin: BinaryIO | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description="Install or verify a DPAPI-protected Worker Pool S3 credential",
    )
    subparsers = parser.add_subparsers(dest="operation", required=True)
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--confirm", required=True)
    subparsers.add_parser("status")
    arguments = parser.parse_args(argv)
    credential: S3Credential | None = None
    try:
        require_windows_host()
        if arguments.operation == "install":
            if arguments.confirm != INSTALL_CONFIRM:
                raise CredentialBootstrapError("credential_confirmation_invalid")
            target = default_credential_path()
            if target.exists() or target.is_symlink():
                raise CredentialBootstrapError("credential_already_installed")
            source = sys.stdin.buffer if stdin is None else stdin
            credential = read_credential_stdin(source)
            result = _install_credential(credential, target)
        else:
            result = credential_status()
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except CredentialBootstrapError as error:
        print(json.dumps(_blocked_status(error.code), ensure_ascii=True, sort_keys=True))
        return 2
    except Exception:
        print(json.dumps(_blocked_status("credential_operation_failed"), sort_keys=True))
        return 3
    finally:
        credential = None


if __name__ == "__main__":
    raise SystemExit(main())
