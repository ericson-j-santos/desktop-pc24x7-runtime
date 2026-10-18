"""Portable encrypted TODO recovery bundle; no network, database or key creation.

Uses an existing RSA recipient; a fresh AES-256-GCM key is wrapped using RSA-OAEP.
Only manifest.json and database.dump enter the encrypted payload, never key files.
On real hosts invoke through Session Launcher/Command Gateway.
"""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
from typing import Iterator

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"TODO-PG-SEALED-V1\0"
MAX_DUMP = 64 * 1024 * 1024
MAX_MANIFEST = 128 * 1024
MAX_ENVELOPE = MAX_DUMP + MAX_MANIFEST + 16384


class SealedBlocked(RuntimeError):
    """Only stable, non-sensitive reason codes leave this module."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SealedBlocked(reason)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def strict_json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "JSON_DUPLICATE_KEY")
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise SealedBlocked("JSON_INVALID") from None
    require(isinstance(result, dict), "JSON_OBJECT_REQUIRED")
    return result


def checked_path(path: Path) -> None:
    require(path.is_absolute() and ".." not in path.parts, "ABSOLUTE_PATH_REQUIRED")
    for item in (path, *path.parents):
        require(not item.is_symlink(), "REPARSE_PATH_REJECTED")
        if hasattr(item, "is_junction"):
            require(not item.is_junction(), "REPARSE_PATH_REJECTED")


def private_path(path: Path, *, create: bool = False) -> None:
    checked_path(path)
    if os.name == "nt":
        # Reuse the existing host-specific owner-only ACL implementation.
        from backup_reqsys_current_dev_postgres import owner_sid, private_acl, assert_private_acl
        sid = owner_sid()
        if create:
            private_acl(path, sid)
        assert_private_acl(path, sid)
    else:
        info = path.stat()
        require(info.st_uid == os.getuid() and not info.st_mode & 0o077, "PRIVATE_PERMISSIONS_REQUIRED")


def read_file(path: Path, limit: int, *, private: bool = False) -> bytes:
    checked_path(path)
    require(path.is_file() and not path.is_symlink(), "REGULAR_FILE_REQUIRED")
    if private:
        private_path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit, "FILE_SIZE_INVALID")
        data = stream.read(limit + 1)
        require(len(data) == info.st_size and len(data) <= limit, "FILE_CHANGED_OR_TOO_LARGE")
        return data


def write_new(path: Path, value: bytes, *, private: bool = False) -> None:
    checked_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        if private:
            private_path(path, create=True)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    if private:
        private_path(path)


@contextmanager
def lock(path: Path) -> Iterator[None]:
    checked_path(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise SealedBlocked("OPERATION_BUSY") from None
    os.close(fd)
    try:
        yield
    finally:
        path.unlink()


def validate_payload(manifest: bytes, archive: bytes) -> dict:
    require(0 < len(manifest) <= MAX_MANIFEST and 5 < len(archive) <= MAX_DUMP, "PAYLOAD_SIZE_INVALID")
    data = strict_json(manifest)
    require(type(data.get("schema_version")) is int and data["schema_version"] == 1, "MANIFEST_INVALID")
    require(isinstance(data.get("correlation_id"), str) and
            re.fullmatch(r"[A-Za-z0-9_.-]{3,96}", data["correlation_id"]) is not None, "CORRELATION_INVALID")
    require(data.get("archive_sha256") == digest(archive) and archive.startswith(b"PGDMP"), "ARCHIVE_INTEGRITY_FAILED")
    return data


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=MAGIC)


def key_id(key) -> str:
    public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    require(isinstance(public, rsa.RSAPublicKey) and 3072 <= public.key_size <= 8192 and
            public.public_numbers().e == 65537, "RSA_RECIPIENT_INVALID")
    return digest(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def encrypt(manifest: bytes, archive: bytes, recipient_pem: bytes) -> bytes:
    validate_payload(manifest, archive)
    try:
        public = serialization.load_pem_public_key(recipient_pem)
        recipient = key_id(public)
    except (ValueError, TypeError):
        raise SealedBlocked("RECIPIENT_INVALID") from None
    key = AESGCM.generate_key(bit_length=256)
    header = canonical({"v": 1, "recipient": recipient,
                        "wrapped": base64.b64encode(public.encrypt(key, oaep())).decode("ascii")})
    nonce = os.urandom(12)
    aad = MAGIC + struct.pack(">I", len(header)) + header
    plain = struct.pack(">I", len(manifest)) + manifest + archive
    return aad + nonce + AESGCM(key).encrypt(nonce, plain, aad)


def inspect_envelope(envelope: bytes, recipient_pem: bytes | None = None) -> dict:
    """Inspect V1 structure/recipient only; this does not authenticate ciphertext."""
    require(isinstance(envelope, bytes) and
            len(MAGIC) + 4 + 12 + 16 < len(envelope) <= MAX_ENVELOPE and
            envelope.startswith(MAGIC), "ENVELOPE_INVALID")
    hlen = struct.unpack(">I", envelope[len(MAGIC):len(MAGIC)+4])[0]
    require(1 <= hlen <= 8192, "HEADER_INVALID")
    end = len(MAGIC) + 4 + hlen
    require(end + 28 < len(envelope), "ENVELOPE_TRUNCATED")
    header = strict_json(envelope[len(MAGIC)+4:end])
    require(set(header) == {"v", "recipient", "wrapped"} and type(header["v"]) is int and
            header["v"] == 1, "HEADER_INVALID")
    require(isinstance(header["recipient"], str) and
            re.fullmatch(r"[0-9a-f]{64}", header["recipient"]) is not None,
            "HEADER_RECIPIENT_INVALID")
    require(isinstance(header["wrapped"], str) and 0 < len(header["wrapped"]) <= 1368,
            "WRAPPED_KEY_INVALID")
    try:
        wrapped = base64.b64decode(header["wrapped"], validate=True)
    except (ValueError, TypeError, UnicodeError):
        raise SealedBlocked("WRAPPED_KEY_INVALID") from None
    require(base64.b64encode(wrapped).decode("ascii") == header["wrapped"],
            "WRAPPED_KEY_INVALID")
    require(384 <= len(wrapped) <= 1024, "WRAPPED_KEY_SIZE_INVALID")
    if recipient_pem is not None:
        try:
            public = serialization.load_pem_public_key(recipient_pem)
            expected = key_id(public)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            raise SealedBlocked("RECIPIENT_INVALID") from None
        require(header["recipient"] == expected, "RECIPIENT_MISMATCH")
        require(len(wrapped) == (public.key_size + 7) // 8, "WRAPPED_KEY_SIZE_INVALID")
    return {"header": header, "header_end": end, "wrapped": wrapped}


def decrypt(envelope: bytes, identity_pem: bytes) -> tuple[bytes, bytes]:
    inspected = inspect_envelope(envelope)
    header, end, wrapped = inspected["header"], inspected["header_end"], inspected["wrapped"]
    try:
        identity = serialization.load_pem_private_key(identity_pem, password=None)
        require(isinstance(identity, rsa.RSAPrivateKey), "IDENTITY_INVALID")
        require(key_id(identity) == header["recipient"], "RECIPIENT_MISMATCH")
        require(len(wrapped) == (identity.key_size + 7) // 8, "WRAPPED_KEY_SIZE_INVALID")
        key = identity.decrypt(wrapped, oaep())
        require(len(key) == 32, "KEY_INVALID")
        plain = AESGCM(key).decrypt(envelope[end:end+12], envelope[end+12:], envelope[:end])
    except (InvalidTag, ValueError, TypeError, UnsupportedAlgorithm):
        raise SealedBlocked("AUTHENTICATION_FAILED") from None
    require(len(plain) >= 4, "PAYLOAD_SIZE_INVALID")
    mlen = struct.unpack(">I", plain[:4])[0]
    require(0 < mlen <= MAX_MANIFEST and 4 + mlen < len(plain), "PAYLOAD_SIZE_INVALID")
    manifest, archive = plain[4:4+mlen], plain[4+mlen:]
    validate_payload(manifest, archive)
    return manifest, archive


def seal(bundle: Path, output: Path, recipient_file: Path) -> dict:
    private_path(bundle)
    require(output.suffix == ".sealed" and output.parent.is_dir(), "SEALED_OUTPUT_REQUIRED")
    require(not output.is_relative_to(bundle), "CIPHERTEXT_MUST_BE_SEPARATE")
    recipient_pem = read_file(recipient_file, 16384)
    receipt_path = output.with_suffix(".sealed.receipt.json")
    with lock(bundle / ".operation.lock"), lock(output.with_suffix(".sealed.lock")):
        manifest = read_file(bundle / "manifest.json", MAX_MANIFEST, private=True)
        archive = read_file(bundle / "database.dump", MAX_DUMP, private=True)
        validate_payload(manifest, archive)
        binding = {"payload_sha256": digest(struct.pack(">I", len(manifest)) + manifest + archive),
                   "recipient": key_id(serialization.load_pem_public_key(recipient_pem))}
        if output.exists():
            previous = strict_json(read_file(receipt_path, 4096))
            require(all(previous.get(k) == v for k, v in binding.items()) and
                    previous.get("ciphertext_sha256") == digest(read_file(output, MAX_ENVELOPE)),
                    "EXISTING_CIPHERTEXT_MISMATCH")
            return {"state": "already_sealed", "ciphertext_sha256": previous["ciphertext_sha256"],
                    "cutover_ready": False}
        require(not receipt_path.exists(), "PARTIAL_OUTPUT_REQUIRES_REVIEW")
        encrypted = encrypt(manifest, archive, recipient_pem)
        write_new(output, encrypted)
        require(read_file(output, MAX_ENVELOPE) == encrypted, "CIPHERTEXT_READBACK_FAILED")
        receipt = {**binding, "ciphertext_sha256": digest(encrypted)}
        write_new(receipt_path, canonical(receipt))
        return {"state": "sealed", "ciphertext_sha256": receipt["ciphertext_sha256"], "cutover_ready": False}


def unseal(source: Path, target: Path, identity_file: Path, expected_sha256: str) -> dict:
    checked_path(target)
    require(target.parent.is_dir() and not identity_file.is_relative_to(target), "TARGET_INVALID")
    # Authentication AND archive digest are checked before creating plaintext output.
    require(isinstance(expected_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
            "TRUSTED_CIPHERTEXT_DIGEST_REQUIRED")
    envelope = read_file(source, MAX_ENVELOPE)
    require(digest(envelope) == expected_sha256, "CIPHERTEXT_DIGEST_MISMATCH")
    manifest, archive = decrypt(envelope, read_file(identity_file, 16384, private=True))
    with lock(target.parent / (target.name + ".unseal.lock")):
        if target.exists():
            private_path(target)
            require(read_file(target/"manifest.json", MAX_MANIFEST, private=True) == manifest and
                    read_file(target/"database.dump", MAX_DUMP, private=True) == archive,
                    "EXISTING_PLAINTEXT_MISMATCH")
            return {"state": "already_unsealed", "cutover_ready": False}
        target.mkdir(mode=0o700)
        private_path(target, create=True)
        write_new(target/"database.dump", archive, private=True)
        write_new(target/"manifest.json", manifest, private=True)
        require(read_file(target/"database.dump", MAX_DUMP, private=True) == archive and
                read_file(target/"manifest.json", MAX_MANIFEST, private=True) == manifest, "PLAINTEXT_READBACK_FAILED")
        return {"state": "unsealed", "cutover_ready": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("seal", "unseal"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    try:
        variable = "TODO_RECOVERY_RECIPIENT_FILE" if args.action == "seal" else "TODO_RECOVERY_IDENTITY_FILE"
        require(bool(os.environ.get(variable)), "EXISTING_KEY_REFERENCE_REQUIRED")
        if args.action == "seal":
            result = seal(args.source, args.destination, Path(os.environ[variable]))
        else:
            result = unseal(args.source, args.destination, Path(os.environ[variable]), args.expected_sha256)
    except SealedBlocked as error:
        result = {"state": "blocked", "reason": str(error), "cutover_ready": False}
    except Exception:
        result = {"state": "blocked", "reason": "SEALED_OPERATION_FAILED", "cutover_ready": False}
    print(json.dumps(result, sort_keys=True))
    return 2 if result["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
