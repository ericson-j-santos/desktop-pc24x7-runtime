"""Cryptographic recovery-key possession proof; no permanent keys or provider access.

Three deliberately separate steps: issue a fresh RSA-OAEP challenge, answer on a
recovery executor, and verify the response at the issuer. A matching answer only
proves key possession at the answering executor; it does NOT establish off-host
custody, trust in that executor, deployment readiness or an approved cutover.
Run only through the governed Session Launcher and Command Gateway on user hosts.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAGIC = b"TODO-PG-SEALED-V1\0"  # Must match pc24x7_todo_sealed.py
PREFIX = b"TODO-KEY-PROOF-V1\0"
PURPOSE = "TODO_PG_RECOVERY_KEY_POSSESSION_V1"
TTL_SECONDS = 900
MAX_JSON_BYTES = 16384
HEX = re.compile(r"[a-f0-9]{64}\Z")
CORRELATION = re.compile(r"[A-Za-z0-9_.-]{3,96}\Z")


class CustodyBlocked(RuntimeError):
    """Only constant error codes, never paths or key bytes."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise CustodyBlocked(code)


def stable_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_json(raw: bytes) -> dict:
    def unique(pairs: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, val in pairs:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = val
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError):
        raise CustodyBlocked("JSON_INVALID") from None
    require(isinstance(value, dict), "OBJECT_REQUIRED")
    return value


def checked(path: Path, *, private: bool, directory: bool = False) -> Path:
    require(path.is_absolute() and ".." not in path.parts, "ABSOLUTE_PATH_REQUIRED")
    for item in (path, *path.parents):
        require(not item.is_symlink(), "LINK_PATH_FORBIDDEN")
        if hasattr(item, "is_junction"):
            require(not item.is_junction(), "LINK_PATH_FORBIDDEN")
    require(path.is_dir() if directory else path.is_file(), "PATH_TYPE_INVALID")
    info = path.stat()
    if not directory:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "REGULAR_FILE_REQUIRED")
    if private:
        if os.name == "nt":
            from backup_reqsys_current_dev_postgres import owner_sid, assert_private_acl
            assert_private_acl(path, owner_sid())
        else:
            require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, "PRIVATE_PERMISSIONS_REQUIRED")
    return path


def load_file(path: Path, *, private: bool = False, limit: int = MAX_JSON_BYTES) -> bytes:
    checked(path, private=private)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit, "FILE_SIZE_INVALID")
        data = stream.read(limit + 1)
        require(len(data) == info.st_size and len(data) <= limit, "FILE_CHANGED")
        return data


def create_private(path: Path, content: bytes) -> None:
    require(path.is_absolute() and ".." not in path.parts, "ABSOLUTE_PATH_REQUIRED")
    checked(path.parent, private=True, directory=True)
    require(not path.is_symlink(), "LINK_PATH_FORBIDDEN")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise CustodyBlocked("EXISTING_OUTPUT_REQUIRES_REVIEW") from None
    with os.fdopen(fd, "wb") as stream:
        if os.name == "nt":
            from backup_reqsys_current_dev_postgres import owner_sid, private_acl
            private_acl(path, owner_sid())
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    checked(path, private=True)


def recipient_id(key: Any) -> str:
    key = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    require(isinstance(key, rsa.RSAPublicKey) and 3072 <= key.key_size <= 8192 and
            key.public_numbers().e == 65537, "RSA_KEY_POLICY_INVALID")
    return sha(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=MAGIC)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_utc(value: Any) -> datetime:
    require(isinstance(value, str) and len(value) == 20 and value.endswith("Z"), "TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CustodyBlocked("TIME_INVALID") from None
    return parsed


def challenge_valid(value: dict, *, at: datetime | None = None) -> None:
    require(set(value) == {"version", "purpose", "correlation_id", "recipient_sha256", "issued_at", "expires_at", "ciphertext_b64"}, "CHALLENGE_FIELDS_INVALID")
    require(type(value["version"]) is int and value["version"] == 1 and value["purpose"] == PURPOSE, "CHALLENGE_VERSION_INVALID")
    require(isinstance(value["correlation_id"], str) and CORRELATION.fullmatch(value["correlation_id"]) is not None, "CORRELATION_INVALID")
    require(isinstance(value["recipient_sha256"], str) and HEX.fullmatch(value["recipient_sha256"]) is not None, "RECIPIENT_INVALID")
    issued, expires = parse_utc(value["issued_at"]), parse_utc(value["expires_at"])
    require(expires - issued == timedelta(seconds=TTL_SECONDS), "TIME_WINDOW_INVALID")
    at = now_utc() if at is None else at
    require(issued - timedelta(seconds=30) <= at <= expires, "CHALLENGE_EXPIRED_OR_FUTURE")
    require(isinstance(value["ciphertext_b64"], str) and len(value["ciphertext_b64"]) <= 2048, "CIPHERTEXT_INVALID")


def challenge_sha(value: dict) -> str:
    return sha(stable_json(value))


def make_proof(nonce: bytes, challenge_hash: str) -> str:
    return hmac.new(nonce, PREFIX + challenge_hash.encode("ascii"), hashlib.sha256).hexdigest()


def issue(out_dir: Path, recipient_file: Path, correlation_id: str, *, at: datetime | None = None) -> dict:
    require(isinstance(correlation_id, str) and CORRELATION.fullmatch(correlation_id) is not None, "CORRELATION_INVALID")
    checked(out_dir, private=True, directory=True)
    challenge_path, receipt_path = out_dir / "challenge.json", out_dir / "issuer-receipt.json"
    try:
        public = serialization.load_pem_public_key(load_file(recipient_file, limit=16384))
        kid = recipient_id(public)
    except (TypeError, ValueError):
        raise CustodyBlocked("PUBLIC_KEY_INVALID") from None
    if challenge_path.exists() or receipt_path.exists():
        require(challenge_path.exists() and receipt_path.exists(), "PARTIAL_ISSUE_REQUIRES_REVIEW")
        challenge = parse_json(load_file(challenge_path, private=True))
        receipt = parse_json(load_file(receipt_path, private=True))
        challenge_valid(challenge, at=at)
        require(set(receipt) == {"version", "correlation_id", "challenge_sha256", "expected_proof_hmac_sha256"} and
                type(receipt["version"]) is int and receipt["version"] == 1 and
                isinstance(receipt["expected_proof_hmac_sha256"], str) and
                HEX.fullmatch(receipt["expected_proof_hmac_sha256"]) is not None and
                receipt["challenge_sha256"] == challenge_sha(challenge) and
                receipt["correlation_id"] == correlation_id and challenge["correlation_id"] == correlation_id and
                challenge["recipient_sha256"] == kid,
                "EXISTING_CHALLENGE_MISMATCH")
        return {"state": "already_issued", "challenge_sha256": challenge_sha(challenge),
                "recipient_sha256": challenge["recipient_sha256"], "offhost_custody_verified": False, "cutover_ready": False}
    secret = os.urandom(32)  # Ephemeral challenge only, not a user credential or RSA key.
    instant = now_utc() if at is None else at
    # Round down to seconds to avoid inconsistent precision in receipts.
    instant = instant.replace(microsecond=0)
    cipher = public.encrypt(PREFIX + secret, oaep())
    challenge = {"version": 1, "purpose": PURPOSE, "correlation_id": correlation_id,
                 "recipient_sha256": kid, "issued_at": utc(instant),
                 "expires_at": utc(instant + timedelta(seconds=TTL_SECONDS)),
                 "ciphertext_b64": base64.b64encode(cipher).decode("ascii")}
    digest = challenge_sha(challenge)
    receipt = {"version": 1, "correlation_id": correlation_id,
               "challenge_sha256": digest, "expected_proof_hmac_sha256": make_proof(secret, digest)}
    # Fail-closed if interrupted between files; no automatic deletion of a partial record.
    create_private(challenge_path, stable_json(challenge) + b"\n")
    create_private(receipt_path, stable_json(receipt) + b"\n")
    return {"state": "issued", "challenge_sha256": digest, "recipient_sha256": kid,
            "offhost_custody_verified": False, "cutover_ready": False}


def answer(challenge_path: Path, response_path: Path, identity_file: Path, trusted_challenge_sha256: str,
           *, at: datetime | None = None) -> dict:
    require(isinstance(trusted_challenge_sha256, str) and HEX.fullmatch(trusted_challenge_sha256) is not None,
            "TRUSTED_CHALLENGE_DIGEST_REQUIRED")
    checked(response_path.parent, private=True, directory=True)
    require(response_path.is_absolute() and ".." not in response_path.parts and not response_path.is_symlink(),
            "RESPONSE_PATH_INVALID")
    challenge = parse_json(load_file(challenge_path))
    challenge_valid(challenge, at=at)
    digest = challenge_sha(challenge)
    require(hmac.compare_digest(trusted_challenge_sha256, digest), "CHALLENGE_HASH_MISMATCH")
    try:
        identity = serialization.load_pem_private_key(load_file(identity_file, private=True, limit=16384), password=None)
        kid = recipient_id(identity)
        require(hmac.compare_digest(kid, challenge["recipient_sha256"]), "IDENTITY_RECIPIENT_MISMATCH")
        cipher = base64.b64decode(challenge["ciphertext_b64"], validate=True)
        nonce = identity.decrypt(cipher, oaep())
        require(len(nonce) == len(PREFIX) + 32 and nonce.startswith(PREFIX), "CHALLENGE_DECRYPTION_INVALID")
        proof = make_proof(nonce[len(PREFIX):], digest)
    except CustodyBlocked:
        raise
    except (TypeError, ValueError):
        raise CustodyBlocked("KEY_RECOVERY_FAILED") from None
    response = {"version": 1, "challenge_sha256": digest, "correlation_id": challenge["correlation_id"],
                "recipient_sha256": kid, "proof_hmac_sha256": proof}
    if response_path.exists():
        existing = parse_json(load_file(response_path, private=True))
        require(existing == response, "EXISTING_RESPONSE_MISMATCH")
        return {"state": "already_answered", "challenge_sha256": digest,
                "cryptographic_match": True, "offhost_custody_verified": False, "cutover_ready": False}
    create_private(response_path, stable_json(response) + b"\n")
    return {"state": "answered", "challenge_sha256": digest,
            "cryptographic_match": True, "offhost_custody_verified": False, "cutover_ready": False}


def verify(challenge_path: Path, issuer_receipt_path: Path, response_path: Path,
           *, at: datetime | None = None) -> dict:
    challenge = parse_json(load_file(challenge_path, private=True))
    challenge_valid(challenge, at=at)
    digest = challenge_sha(challenge)
    receipt = parse_json(load_file(issuer_receipt_path, private=True))
    response = parse_json(load_file(response_path))
    require(set(receipt) == {"version", "correlation_id", "challenge_sha256", "expected_proof_hmac_sha256"} and
            receipt["version"] == 1 and receipt["correlation_id"] == challenge["correlation_id"] and
            receipt["challenge_sha256"] == digest and isinstance(receipt["expected_proof_hmac_sha256"], str) and
            HEX.fullmatch(receipt["expected_proof_hmac_sha256"]) is not None,
            "ISSUER_RECEIPT_INVALID")
    require(set(response) == {"version", "challenge_sha256", "correlation_id", "recipient_sha256", "proof_hmac_sha256"} and
            response["version"] == 1 and response["challenge_sha256"] == digest and
            response["correlation_id"] == challenge["correlation_id"] and
            response["recipient_sha256"] == challenge["recipient_sha256"] and
            isinstance(response["proof_hmac_sha256"], str) and HEX.fullmatch(response["proof_hmac_sha256"]) is not None,
            "RESPONSE_INVALID")
    require(hmac.compare_digest(response["proof_hmac_sha256"], receipt["expected_proof_hmac_sha256"]),
            "PROOF_MISMATCH")
    return {"state": "key_possession_verified", "recipient_sha256": challenge["recipient_sha256"],
            "challenge_sha256": digest, "cryptographic_match": True,
            "offhost_custody_verified": False, "cutover_ready": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("issue", "answer", "verify"))
    parser.add_argument("--challenge-dir", type=Path)
    parser.add_argument("--challenge", type=Path)
    parser.add_argument("--response", type=Path)
    parser.add_argument("--issuer-receipt", type=Path)
    parser.add_argument("--expected-challenge-sha256")
    parser.add_argument("--correlation-id")
    args = parser.parse_args()
    try:
        if args.action == "issue":
            require(args.challenge_dir is not None and args.correlation_id is not None and
                    bool(os.environ.get("TODO_RECOVERY_RECIPIENT_FILE")), "ISSUE_INPUT_REQUIRED")
            result = issue(args.challenge_dir, Path(os.environ["TODO_RECOVERY_RECIPIENT_FILE"]), args.correlation_id)
        elif args.action == "answer":
            require(args.challenge is not None and args.response is not None and
                    bool(os.environ.get("TODO_RECOVERY_IDENTITY_FILE")), "ANSWER_INPUT_REQUIRED")
            result = answer(args.challenge, args.response, Path(os.environ["TODO_RECOVERY_IDENTITY_FILE"]),
                            args.expected_challenge_sha256)
        else:
            require(args.challenge is not None and args.issuer_receipt is not None and args.response is not None,
                    "VERIFY_INPUT_REQUIRED")
            result = verify(args.challenge, args.issuer_receipt, args.response)
    except CustodyBlocked as error:
        result = {"state": "blocked", "reason": str(error), "cutover_ready": False}
    except Exception:
        result = {"state": "blocked", "reason": "CUSTODY_PREFLIGHT_FAILED", "cutover_ready": False}
    print(json.dumps(result, sort_keys=True))
    return 2 if result["state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
