"""Tests for the bounded, offline inventory, including adversarial controls."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest
from scripts import ollama_windows_offline_inventory as inv


def roots(tmp_path):
    user = tmp_path / "User"
    local = user / "AppData" / "Local"
    programfiles = tmp_path / "ProgramFiles"
    for p in (local, programfiles):
        p.mkdir(parents=True)
    return user, local, programfiles


def fake_pe():
    raw = bytearray(200)
    raw[:2] = b"MZ"
    raw[0x3c:0x40] = (80).to_bytes(4, "little")
    raw[80:84] = b"PE\x00\x00"
    return bytes(raw)


def fake_model(user):
    root = user / ".ollama" / "models"
    manifest = root / "manifests" / "registry.ollama.ai" / "library" / "qwen2.5-coder" / "7b"
    manifest.parent.mkdir(parents=True)
    digests = [hashlib.sha256(b"config").hexdigest(), hashlib.sha256(b"weight").hexdigest()]
    data = {"schemaVersion": 2, "config": {"digest": "sha256:" + digests[0], "size": 2},
            "layers": [{"digest": "sha256:" + digests[1], "size": 4}]}
    manifest.write_text(json.dumps(data))
    blobs = root / "blobs"
    blobs.mkdir()
    (blobs / ("sha256-" + digests[0])).write_bytes(b"ok")
    (blobs / ("sha256-" + digests[1])).write_bytes(b"pass")
    return manifest


def run(user, local, programfiles):
    return inv.collect(host="DESKTOP-RP23OGS", platform="win32", localappdata=local,
                       userprofile=user, programfiles=programfiles)


def test_missing_is_safe_and_idempotent(tmp_path):
    user, local, programs = roots(tmp_path)
    a = run(user, local, programs)
    assert a == run(user, local, programs)
    assert a["standard_model"]["state"] == "standard_manifest_missing"
    assert all(x["state"] == "missing" for x in a["binary_candidates"])
    assert a["network_used"] is a["host_mutated"] is a["launch_authorized"] is False
    assert a["model_calls"] == 0


def test_complete_offline_presence_and_sha(tmp_path):
    user, local, programs = roots(tmp_path)
    exe = local / "Programs" / "Ollama" / "ollama.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(fake_pe())
    fake_model(user)
    report = run(user, local, programs)
    assert report["binary_candidates"][0]["sha256"] == hashlib.sha256(fake_pe()).hexdigest()
    assert report["binary_candidates"][0]["authenticode_verified"] is False
    assert report["standard_model"]["state"] == "standard_manifest_and_layers_present"
    assert report["standard_model"]["descriptors_checked"] == 2
    assert report["standard_model"]["weights_integrity_verified"] is False
    assert report == run(user, local, programs)


@pytest.mark.parametrize("host,platform", [("WRONG", "win32"), ("DESKTOP-RP23OGS", "linux")])
def test_host_or_platform_rejected_before_filesystem(tmp_path, host, platform):
    user, local, programs = roots(tmp_path)
    with patch.object(inv, "_hash_exe", side_effect=AssertionError("read before identity")):
        with pytest.raises(inv.InventoryBlocked, match="host_or_platform_rejected"):
            inv.collect(host=host, platform=platform, localappdata=local,
                        userprofile=user, programfiles=programs)


def test_profile_traversal_rejected(tmp_path):
    user, local, programs = roots(tmp_path)
    with pytest.raises(inv.InventoryBlocked, match="profile_location_rejected"):
        inv.collect(host="DESKTOP-RP23OGS", platform="win32", localappdata=local.parent,
                    userprofile=user, programfiles=programs)


def test_symlink_executable_refused(tmp_path):
    user, local, programs = roots(tmp_path)
    exe = local / "Programs" / "Ollama" / "ollama.exe"
    exe.parent.mkdir(parents=True)
    source = tmp_path / "secret.txt"
    source.write_text("do not read")
    try:
        exe.symlink_to(source)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(inv.InventoryBlocked, match="reparse_path_rejected"):
        run(user, local, programs)


def test_model_blob_redirect_rejected(tmp_path):
    user, local, programs = roots(tmp_path)
    fake_model(user)
    blob = next((user / ".ollama" / "models" / "blobs").iterdir())
    content = blob.read_bytes()
    blob.unlink()
    src = tmp_path / "secret.txt"
    src.write_bytes(content)
    try:
        blob.symlink_to(src)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(inv.InventoryBlocked, match="reparse_path_rejected"):
        run(user, local, programs)


def test_bad_manifest_schema_and_layer_size(tmp_path):
    user, local, programs = roots(tmp_path)
    manifest = fake_model(user)
    data = json.loads(manifest.read_text())
    data["layers"][0]["digest"] = "sha256:../../secret"
    manifest.write_text(json.dumps(data))
    with pytest.raises(inv.InventoryBlocked, match="invalid_model_descriptor"):
        run(user, local, programs)
    data["layers"][0]["digest"] = "sha256:" + hashlib.sha256(b"weight").hexdigest()
    data["layers"][0]["size"] = 5
    manifest.write_text(json.dumps(data))
    assert run(user, local, programs)["standard_model"]["state"] == "layer_missing_or_size_mismatch"


def test_invalid_executable_not_accepted(tmp_path):
    user, local, programs = roots(tmp_path)
    exe = local / "Programs" / "Ollama" / "ollama.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"fake executable")
    with pytest.raises(inv.InventoryBlocked, match="not_pe_executable"):
        run(user, local, programs)


def test_source_has_no_network_process_or_mutation_calls():
    code = Path(inv.__file__).read_text()
    for bad in ("subprocess", "urllib", "socket.connect", ".write_bytes(", ".write_text(",
                "os.system", "shutil", "Popen", "win32api", "ctypes"):
        assert bad not in code
