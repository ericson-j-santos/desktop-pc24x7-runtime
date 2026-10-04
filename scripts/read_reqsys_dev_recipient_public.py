"""Read only the fixed PC24x7 DEV migration recipient's public identity."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import socket
import stat
from pathlib import Path

TARGET_HOST = "DESKTOP-PDQK954"
SCHEMA = "reqsys-dev-noteri-pc24x7-backup-v1"
CONFIRMATION = "READ-PC24X7-DEV-RECIPIENT-PUBLIC"
MAX_PUBLIC_JSON_BYTES = 8192
PUBLIC_FIELDS = {"schema", "target_host", "public_key_der_b64", "recipient_sha256"}
RSA_ALGORITHM_IDENTIFIER = bytes.fromhex("06092a864886f70d0101010500")


class PublicReadError(RuntimeError):
    pass


def reject(code: str) -> None:
    raise PublicReadError(code)


def validate_host() -> None:
    if os.name != "nt" or socket.gethostname().casefold() != TARGET_HOST.casefold():
        reject("fixed_pc24x7_host_required")


def no_reparse(path: Path) -> None:
    for candidate in (path, *path.parents):
        try:
            information = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(information.st_mode) or (
            getattr(information, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            reject("public_path_reparse_rejected")


def unique_fields(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            reject("public_json_duplicate_field")
        result[key] = value
    return result


def der_value(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset < 0 or offset + 2 > len(data) or data[offset] != expected_tag:
        reject("public_rsa_der_invalid")
    length_byte = data[offset + 1]
    offset += 2
    if length_byte < 128:
        size = length_byte
    else:
        count = length_byte & 0x7F
        if count not in (1, 2) or offset + count > len(data):
            reject("public_rsa_der_invalid")
        encoded = data[offset:offset + count]
        if encoded[0] == 0:
            reject("public_rsa_der_invalid")
        size = int.from_bytes(encoded, "big")
        if size < 128:
            reject("public_rsa_der_invalid")
        offset += count
    end = offset + size
    if end > len(data):
        reject("public_rsa_der_invalid")
    return data[offset:end], end


def validate_public_der(data: bytes) -> None:
    sequence, end = der_value(data, 0, 0x30)
    if end != len(data):
        reject("public_rsa_der_invalid")
    algorithm, offset = der_value(sequence, 0, 0x30)
    if algorithm != RSA_ALGORITHM_IDENTIFIER:
        reject("public_rsa_algorithm_invalid")
    bit_string, end = der_value(sequence, offset, 0x03)
    if end != len(sequence) or not bit_string or bit_string[0] != 0:
        reject("public_rsa_der_invalid")
    rsa_values, end = der_value(bit_string, 1, 0x30)
    if end != len(bit_string):
        reject("public_rsa_der_invalid")
    modulus, offset = der_value(rsa_values, 0, 0x02)
    exponent, end = der_value(rsa_values, offset, 0x02)
    if (end != len(rsa_values) or len(modulus) != 385 or modulus[0] != 0
            or not modulus[1] & 0x80 or not modulus[-1] & 1
            or exponent != b"\x01\x00\x01"):
        reject("public_rsa_3072_65537_required")


def validate_public_config(encoded: bytes) -> dict:
    if len(encoded) > MAX_PUBLIC_JSON_BYTES:
        reject("public_json_too_large")
    try:
        config = json.loads(encoded, object_pairs_hook=unique_fields)
    except (ValueError, UnicodeError):
        reject("public_json_invalid")
    if not isinstance(config, dict) or set(config) != PUBLIC_FIELDS:
        reject("public_schema_fields_invalid")
    if config["schema"] != SCHEMA or config["target_host"] != TARGET_HOST:
        reject("public_context_invalid")
    key_b64, expected_digest = config["public_key_der_b64"], config["recipient_sha256"]
    if (not isinstance(key_b64, str) or len(key_b64) > 1368
            or not isinstance(expected_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)):
        reject("public_identity_encoding_invalid")
    try:
        public_der = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        reject("public_identity_encoding_invalid")
    if not public_der or len(public_der) > 1024:
        reject("public_identity_encoding_invalid")
    if base64.b64encode(public_der).decode("ascii") != key_b64:
        reject("public_identity_encoding_invalid")
    if not hmac.compare_digest(hashlib.sha256(public_der).hexdigest(), expected_digest):
        reject("public_identity_digest_mismatch")
    validate_public_der(public_der)
    return {key: config[key] for key in sorted(PUBLIC_FIELDS)}


def read_fixed_public_identity() -> dict:
    validate_host()
    raw_base = os.environ.get("LOCALAPPDATA", "")
    if not raw_base or not Path(raw_base).is_absolute():
        reject("fixed_localappdata_required")
    public_file = (Path(raw_base) / "ReqSys" / "SelfHostedDev" / "Migration"
                   / "receiver-public-key.json")
    no_reparse(public_file)
    try:
        with public_file.open("rb") as stream:
            encoded = stream.read(MAX_PUBLIC_JSON_BYTES + 1)
    except OSError:
        reject("fixed_public_identity_unavailable")
    config = validate_public_config(encoded)
    return {"ok": True, "target_host": TARGET_HOST, "public_recipient": config,
            "private_identity_read": False, "files_read": 1, "production_touched": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    try:
        if args.confirm != CONFIRMATION:
            reject("fixed_confirmation_required")
        result = read_fixed_public_identity()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except PublicReadError as exc:
        print(json.dumps({"ok": False, "code": str(exc)}, separators=(",", ":")))
        return 1
    except Exception as exc:
        print(json.dumps({"ok": False, "code": "public_identity_read_failed",
                          "error_type": type(exc).__name__}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
