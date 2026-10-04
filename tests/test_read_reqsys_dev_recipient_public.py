from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "read_reqsys_dev_recipient_public.py"
SPEC = importlib.util.spec_from_file_location("read_reqsys_dev_recipient_public", SCRIPT)
assert SPEC and SPEC.loader
reader = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reader)


def tlv(tag: int, value: bytes) -> bytes:
    size = len(value)
    if size < 128:
        length = bytes([size])
    else:
        encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + value


def public_config() -> dict:
    # Synthetic public-only RSA structure; no private fixture material.
    modulus = b"\x00\x80" + b"\x00" * 382 + b"\x01"
    rsa_values = tlv(0x30, tlv(0x02, modulus) + tlv(0x02, b"\x01\x00\x01"))
    der = tlv(0x30, tlv(0x30, reader.RSA_ALGORITHM_IDENTIFIER) + tlv(0x03, b"\x00" + rsa_values))
    return {"schema": reader.SCHEMA, "target_host": reader.TARGET_HOST,
            "public_key_der_b64": base64.b64encode(der).decode("ascii"),
            "recipient_sha256": hashlib.sha256(der).hexdigest()}


def test_valid_public_schema_and_rsa_structure() -> None:
    config = public_config()
    assert reader.validate_public_config(json.dumps(config).encode()) == config


@pytest.mark.parametrize("field,value,code", [
    ("schema", "other", "public_context_invalid"),
    ("target_host", "Noteri", "public_context_invalid"),
    ("recipient_sha256", "0" * 64, "public_identity_digest_mismatch"),
    ("public_key_der_b64", "not base64", "public_identity_encoding_invalid"),
    ("private_key", "must never emit", "public_schema_fields_invalid"),
])
def test_invalid_or_private_fields_fail_closed(field: str, value: str, code: str) -> None:
    config = public_config()
    config[field] = value
    with pytest.raises(reader.PublicReadError, match=code):
        reader.validate_public_config(json.dumps(config).encode())


def test_non_rsa_data_cannot_be_printed_as_a_public_identity() -> None:
    config = public_config()
    invalid = b"arbitrary confidential content"
    config.update(public_key_der_b64=base64.b64encode(invalid).decode("ascii"),
                  recipient_sha256=hashlib.sha256(invalid).hexdigest())
    with pytest.raises(reader.PublicReadError, match="public_rsa_der_invalid"):
        reader.validate_public_config(json.dumps(config).encode())


def test_oversized_and_duplicate_json_rejected() -> None:
    with pytest.raises(reader.PublicReadError, match="public_json_too_large"):
        reader.validate_public_config(b" " * (reader.MAX_PUBLIC_JSON_BYTES + 1))
    with pytest.raises(reader.PublicReadError, match="public_json_duplicate_field"):
        reader.validate_public_config(b'{"schema":"one","schema":"two"}')


def test_reads_exactly_one_public_file_and_never_private_identity(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "ReqSys" / "SelfHostedDev" / "Migration"
    root.mkdir(parents=True)
    public = root / "receiver-public-key.json"
    public.write_text(json.dumps(public_config()), encoding="utf-8")
    (root / "receiver-private-key.dpapi").write_bytes(b"must-never-read")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(reader, "validate_host", lambda: None)
    opened = []
    original = Path.open

    def spy(path: Path, *args, **kwargs):
        opened.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", spy)
    result = reader.read_fixed_public_identity()
    assert opened == [public]
    assert result["ok"] is True and result["private_identity_read"] is False
    assert result["public_recipient"] == public_config()


def test_wrong_physical_host_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reader.socket, "gethostname", lambda: "unrelated-host")
    with pytest.raises(reader.PublicReadError, match="fixed_pc24x7_host_required"):
        reader.validate_host()


def test_symlink_to_private_file_is_rejected_before_reading(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "ReqSys" / "SelfHostedDev" / "Migration"
    root.mkdir(parents=True)
    private = root / "receiver-private-key.dpapi"
    private.write_bytes(b"must-never-read")
    try:
        (root / "receiver-public-key.json").symlink_to(private)
    except OSError:
        pytest.skip("host cannot create symlink fixture")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(reader, "validate_host", lambda: None)
    with pytest.raises(reader.PublicReadError, match="public_path_reparse_rejected"):
        reader.read_fixed_public_identity()
