"""Real cryptography/filesystem tests. All keys and data are synthetic."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("sealed_test", ROOT/"scripts/pc24x7_todo_sealed.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


@pytest.fixture(scope="module")
def keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return public, private


@pytest.fixture
def fixture(tmp_path, keys):
    source = tmp_path/"source"
    source.mkdir(mode=0o700)
    s.private_path(source, create=True)
    archive = b"PGDMP-synthetic-private-content"
    manifest = s.canonical({"schema_version":1,"correlation_id":"synthetic-test",
                           "archive_sha256":s.digest(archive)})
    for name, value in (("database.dump", archive), ("manifest.json", manifest)):
        s.write_new(source/name, value, private=True)
    public_file, private_file = tmp_path/"recipient.pem", tmp_path/"identity.pem"
    s.write_new(public_file, keys[0])
    s.write_new(private_file, keys[1], private=True)
    return source, tmp_path/"copy.sealed", public_file, private_file, manifest, archive


def test_seal_unseal_and_replay(fixture):
    source, output, public, private, manifest, archive = fixture
    first = s.seal(source, output, public)
    timestamp = output.stat().st_mtime_ns
    assert first["state"] == "sealed" and not first["cutover_ready"]
    assert s.seal(source, output, public)["state"] == "already_sealed"
    assert output.stat().st_mtime_ns == timestamp
    encrypted = output.read_bytes()
    assert archive not in encrypted and b"PRIVATE KEY" not in encrypted
    destination = source.parent/"decoded"
    assert s.unseal(output, destination, private, first["ciphertext_sha256"])["state"] == "unsealed"
    assert (destination/"database.dump").read_bytes() == archive
    assert (destination/"manifest.json").read_bytes() == manifest
    before = (destination/"database.dump").stat().st_mtime_ns
    assert s.unseal(output, destination, private, first["ciphertext_sha256"])["state"] == "already_unsealed"
    assert (destination/"database.dump").stat().st_mtime_ns == before


@pytest.mark.parametrize("position", [0, 20, -1, -17])
def test_tamper_rejected_before_plaintext(fixture, position):
    source, output, public, private, _, _ = fixture
    s.seal(source, output, public)
    data = bytearray(output.read_bytes())
    data[position] ^= 1
    output.write_bytes(data)
    destination = source.parent/"decoded"
    with pytest.raises(s.SealedBlocked):
        s.unseal(output, destination, private, s.digest(data))
    assert not destination.exists()


def test_wrong_identity_rejected_without_output(fixture):
    source, output, public, private, _, _ = fixture
    receipt = s.seal(source, output, public)
    different = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private.write_bytes(different.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(s.SealedBlocked, match="RECIPIENT_MISMATCH"):
        s.unseal(output, source.parent/"decoded", private, receipt["ciphertext_sha256"])
    assert not (source.parent/"decoded").exists()


@pytest.mark.parametrize("expected", [None, "bad", "0"*64])
def test_trusted_cipher_digest_required(fixture, expected):
    source, output, public, private, _, _ = fixture
    s.seal(source, output, public)
    with pytest.raises(s.SealedBlocked, match="DIGEST"):
        s.unseal(output, source.parent/"decoded", private, expected)
    assert not (source.parent/"decoded").exists()


def test_restore_destination_not_overwritten(fixture):
    source, output, public, private, _, _ = fixture
    receipt = s.seal(source, output, public)
    target = source.parent/"decoded"
    s.unseal(output, target, private, receipt["ciphertext_sha256"])
    (target/"database.dump").write_bytes(b"changed")
    with pytest.raises(s.SealedBlocked, match="EXISTING_PLAINTEXT"):
        s.unseal(output, target, private, receipt["ciphertext_sha256"])
    assert (target/"database.dump").read_bytes() == b"changed"


def test_changed_archive_rejected_before_output(fixture):
    source, output, public, _, _, _ = fixture
    (source/"database.dump").write_bytes(b"PGDMP-corrupt")
    with pytest.raises(s.SealedBlocked, match="ARCHIVE_INTEGRITY"):
        s.seal(source, output, public)
    assert not output.exists()


def test_existing_ciphertext_not_overwritten(fixture):
    source, output, public, _, _, _ = fixture
    s.seal(source, output, public)
    output.write_bytes(b"changed")
    with pytest.raises(s.SealedBlocked, match="EXISTING_CIPHERTEXT"):
        s.seal(source, output, public)
    assert output.read_bytes() == b"changed"


def test_partial_output_preserved(fixture):
    source, output, public, _, _, _ = fixture
    output.with_suffix(".sealed.receipt.json").write_text("{}")
    with pytest.raises(s.SealedBlocked, match="PARTIAL"):
        s.seal(source, output, public)
    assert not output.exists()


def test_concurrent_capture_lock_preserved(fixture):
    source, output, public, _, _, _ = fixture
    (source/".operation.lock").write_text("other")
    with pytest.raises(s.SealedBlocked, match="BUSY"):
        s.seal(source, output, public)
    assert (source/".operation.lock").read_text() == "other"


def test_output_lock_preserved(fixture):
    source, output, public, _, _, _ = fixture
    output.with_suffix(".sealed.lock").write_text("other")
    with pytest.raises(s.SealedBlocked, match="BUSY"):
        s.seal(source, output, public)
    assert not (source/".operation.lock").exists()
    assert output.with_suffix(".sealed.lock").read_text() == "other"


def test_payload_is_randomized(keys, fixture):
    *_, manifest, archive = fixture
    a=s.encrypt(manifest, archive, keys[0])
    b=s.encrypt(manifest, archive, keys[0])
    assert a != b
    assert s.decrypt(a, keys[1]) == s.decrypt(b, keys[1]) == (manifest, archive)


def test_weak_rsa_is_blocked(fixture):
    *_, manifest, archive = fixture
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public=key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(s.SealedBlocked, match="RSA_RECIPIENT"):
        s.encrypt(manifest, archive, public)


@pytest.mark.parametrize("payload", [b"{}", b'{"schema_version":1,"schema_version":1}', b"[]", b"NaN"])
def test_invalid_manifest_cannot_be_sealed(keys, payload):
    with pytest.raises(s.SealedBlocked):
        s.encrypt(payload, b"PGDMP-example", keys[0])


@pytest.mark.parametrize("cut", [0, 10, 100, 1000])
def test_truncated_cipher_rejected(keys, fixture, cut):
    *_, manifest, archive = fixture
    data=s.encrypt(manifest, archive, keys[0])
    with pytest.raises(s.SealedBlocked):
        s.decrypt(data[:min(cut, len(data)-1)], keys[1])


def test_path_parent_traversal_rejected(tmp_path):
    with pytest.raises(s.SealedBlocked, match="ABSOLUTE"):
        s.checked_path(tmp_path/".."/"elsewhere")


def test_size_limit_before_read(tmp_path):
    f=tmp_path/"large";f.write_bytes(b"x"*10)
    with pytest.raises(s.SealedBlocked, match="SIZE"):
        s.read_file(f, 9)


def test_no_key_generation_or_network_in_cli():
    text=(ROOT/"scripts/pc24x7_todo_sealed.py").read_text()
    assert "rsa.generate_private_key" not in text
    assert "requests." not in text and "urlopen" not in text and "subprocess" not in text
    assert 'choices=("seal", "unseal")' in text


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode guard; Windows uses real owner-only ACL checks in fixtures")
def test_world_readable_private_identity_blocked(fixture):
    source, output, public, private, _, _ = fixture
    first=s.seal(source, output, public)
    private.chmod(0o644)
    with pytest.raises(s.SealedBlocked, match="PRIVATE_PERMISSIONS"):
        s.unseal(output, source.parent/"decoded", private, first["ciphertext_sha256"])
    assert not (source.parent/"decoded").exists()


def _replace_header(envelope, raw):
    end = s.inspect_envelope(envelope)["header_end"]
    return s.MAGIC + s.struct.pack(">I", len(raw)) + raw + envelope[end:]


def test_inspection_preserves_v1_encryption_roundtrip(keys):
    archive = b"PGDMP-synthetic-envelope-inspection"
    manifest = s.canonical({"schema_version": 1, "correlation_id": "envelope-test",
                            "archive_sha256": s.digest(archive)})
    envelope = s.encrypt(manifest, archive, keys[0])
    inspected = s.inspect_envelope(envelope, keys[0])
    assert inspected["header"]["recipient"] == s.key_id(
        serialization.load_pem_public_key(keys[0]))
    assert len(inspected["wrapped"]) == 384
    assert s.decrypt(envelope, keys[1]) == (manifest, archive)


@pytest.mark.parametrize("case,reason", [
    ("duplicate", "JSON_DUPLICATE_KEY"),
    ("boolean_version", "HEADER_INVALID"),
    ("extra_field", "HEADER_INVALID"),
    ("bad_recipient", "HEADER_RECIPIENT_INVALID"),
    ("bad_base64", "WRAPPED_KEY_INVALID"),
    ("short_wrapped", "WRAPPED_KEY_SIZE_INVALID"),
    ("wrong_rsa_length", "WRAPPED_KEY_SIZE_INVALID"),
    ("truncated", "ENVELOPE_TRUNCATED"),
])
def test_inspection_rejects_invalid_headers(keys, case, reason):
    archive = b"PGDMP-synthetic-header-test"
    manifest = s.canonical({"schema_version": 1, "correlation_id": "header-test",
                            "archive_sha256": s.digest(archive)})
    envelope = s.encrypt(manifest, archive, keys[0])
    header = dict(s.inspect_envelope(envelope)["header"])
    if case == "duplicate":
        raw = s.canonical(header).replace(b'"v":1', b'"v":1,"v":1')
    elif case == "truncated":
        malformed = s.MAGIC + s.struct.pack(">I", 8192) + b"x" * 64
        with pytest.raises(s.SealedBlocked, match=reason):
            s.inspect_envelope(malformed, keys[0])
        return
    else:
        if case == "boolean_version":
            header["v"] = True
        elif case == "extra_field":
            header["unexpected"] = "value"
        elif case == "bad_recipient":
            header["recipient"] = "invalid"
        elif case == "bad_base64":
            header["wrapped"] = "%%%invalid%%%"
        elif case == "short_wrapped":
            header["wrapped"] = s.base64.b64encode(b"x" * 383).decode("ascii")
        elif case == "wrong_rsa_length":
            header["wrapped"] = s.base64.b64encode(b"x" * 385).decode("ascii")
        raw = s.canonical(header)
    with pytest.raises(s.SealedBlocked, match=reason):
        s.inspect_envelope(_replace_header(envelope, raw), keys[0])


def test_structural_inspection_does_not_claim_gcm_authentication(keys):
    archive = b"PGDMP-synthetic-auth-control"
    manifest = s.canonical({"schema_version": 1, "correlation_id": "auth-control",
                            "archive_sha256": s.digest(archive)})
    envelope = s.encrypt(manifest, archive, keys[0])
    tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
    # Header inspection cannot prove ciphertext authentication without the private key.
    assert s.inspect_envelope(tampered, keys[0])["header"]["recipient"]
    with pytest.raises(s.SealedBlocked, match="AUTHENTICATION_FAILED"):
        s.decrypt(tampered, keys[1])
