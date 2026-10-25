"""Positive/negative/replay controls for issue-8 physical read-only inventory.

Fixtures are synthetic directories; they do not prove the Dell is accessible.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from scripts import issue8_sandbox_residual_probe as probe


def fixture(tmp_path):
    workers = tmp_path / "workers"
    workers.mkdir()
    old = workers / probe.WORKTREE
    old.mkdir()
    scratch = old / "issue8-qwen-fixture"
    scratch.mkdir()
    (scratch / "repair-state").mkdir()
    (scratch / "repair-state" / "receipt.json").write_text("{}", encoding="utf-8")
    (scratch / "worker.db").write_bytes(b"SQLite fixture")
    bundle = b"# valid bounded sample\n" * 20
    (scratch / "change.bundle").write_bytes(bundle)
    return workers, scratch, bundle


def test_read_only_inventory_and_repeat_are_identical(tmp_path):
    workers, scratch, blob = fixture(tmp_path)
    assert probe.confined_existing_worktree(workers) == scratch.parent
    checker = lambda _path, _isdir: 0
    first = probe.inventory_sandbox(scratch, check=checker)
    second = probe.inventory_sandbox(scratch, check=checker)
    assert first == second
    assert first["bundle_found"] is True
    assert first["bundle_bytes"] == len(blob)
    assert first["bundle_sha256"] == hashlib.sha256(blob).hexdigest()
    assert first["model_receipt_count"] == 1
    assert first["sqlite_file_count"] == 1
    assert first["sharing_violation_count"] == 0
    assert first["historical_lock_identity_proved"] is False
    assert (scratch / "change.bundle").read_bytes() == blob


def test_read_only_probe_detects_access_and_sharing_issues(tmp_path):
    _, scratch, _ = fixture(tmp_path)
    error_map = {"worker.db": 32, "receipt.json": 5}
    def check(path, _isdir):
        return error_map.get(path.name, 0)
    report = probe.inventory_sandbox(scratch, check=check)
    assert report["sharing_violation_count"] == 1
    assert report["access_denied_count"] == 1
    assert report["historical_lock_identity_proved"] is False


def test_rejects_wrong_or_missing_worktree(tmp_path):
    workers = tmp_path / "workers"
    workers.mkdir()
    with pytest.raises(probe.ProbeBlocked, match="probe_failed_worktree_unavailable"):
        probe.confined_existing_worktree(workers)
    with pytest.raises(probe.ProbeBlocked, match="probe_root_not_verified"):
        probe.confined_existing_worktree(tmp_path / "nonexistent")


def test_inventory_size_cap_rejects_partial_success(tmp_path):
    _, scratch, _ = fixture(tmp_path)
    with pytest.raises(probe.ProbeBlocked, match="probe_inventory_limit_or_link"):
        probe.inventory_sandbox(scratch, check=lambda *_: 0, max_entries=2)


def test_empty_and_foreign_sandbox_denied(tmp_path):
    folder = tmp_path / "other-scratch"
    folder.mkdir()
    with pytest.raises(probe.ProbeBlocked, match="probe_sandbox_scope_invalid"):
        probe.inventory_sandbox(folder, check=lambda *_: 0)


def test_rejects_symlink_without_following(tmp_path):
    _, scratch, _ = fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "secret"
    marker.write_text("untouched", encoding="utf-8")
    try:
        (scratch / "redirect").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation forbidden by OS")
    with pytest.raises(probe.ProbeBlocked, match="probe_inventory_limit_or_link"):
        probe.inventory_sandbox(scratch, check=lambda *_: 0)
    assert marker.read_text(encoding="utf-8") == "untouched"


def test_oversized_bundle_rejected(tmp_path):
    _, scratch, _ = fixture(tmp_path)
    (scratch / "change.bundle").write_bytes(b"x" * (probe.MAX_BUNDLE_BYTES + 1))
    with pytest.raises(probe.ProbeBlocked, match="probe_bundle_size_invalid"):
        probe.inventory_sandbox(scratch, check=lambda *_: 0)


def test_no_write_or_execution_surface_in_probe_source():
    source = (Path(__file__).resolve().parents[1] /
              "scripts" / "issue8_sandbox_residual_probe.py").read_text("utf-8")
    for illegal in ("git push", "ollama", "shutil.rmtree(",
                    "subprocess.run(", "Path.write_bytes(", "os.remove(",
                    "os.unlink(", "create_pull_request", "rm -rf"):
        if illegal == "ollama":
            # Docstring explicitly states it is not invoked.
            assert "import ollama" not in source.lower()
        else:
            assert illegal not in source.lower()
    assert 'RUN_ID = 40214413825' in source
    assert 'RUN_SHA = "50d35e3126d68872c9b3c9d7edde34878d39508e"' in source
