from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "materialize_reqsys_self_hosted_dev_source.py"
SPEC = importlib.util.spec_from_file_location("materialize_reqsys_self_hosted_dev_source", SCRIPT)
assert SPEC and SPEC.loader
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)
SHA = "a" * 40


def test_git_longpaths_is_scoped_and_global_rewrites_stay_disabled(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def run(arguments, **options):
        captured.update(arguments=arguments, options=options)
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(source.subprocess, "run", run)
    assert source.git(["rev-parse", "HEAD"], tmp_path) == "ok"
    assert captured["arguments"] == ["git", "-c", "core.longpaths=true", "rev-parse", "HEAD"]
    options = captured["options"]
    assert options["env"]["GIT_CONFIG_GLOBAL"] == source.os.devnull
    assert options["env"]["GIT_CONFIG_NOSYSTEM"] == "1"
    assert options["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert options["shell"] is False


@pytest.mark.parametrize("stderr,code", [
    ("unable to create: Filename too long", "SOURCE_GIT_FILENAME_TOO_LONG"),
    ("error: invalid path", "SOURCE_GIT_INVALID_PATH"),
    ("Permission denied", "SOURCE_GIT_PERMISSION_DENIED"),
    ("Could not resolve host", "SOURCE_GIT_NETWORK_UNAVAILABLE"),
    ("Authentication failed: never expose token", "SOURCE_GIT_AUTH_UNAVAILABLE"),
    ("other private error content", "SOURCE_GIT_FAILED"),
])
def test_failure_classification_never_returns_stderr(stderr: str, code: str) -> None:
    assert source.git_failure_code(stderr) == code


def fake_git(tmp_path: Path, *, dirty: bool = False):
    calls = []

    def git(args, cwd):
        calls.append((args, cwd))
        if args[0] == "clone":
            target = Path(args[-1])
            target.mkdir()
            (target / ".git").mkdir()
            return ""
        if args == ["rev-parse", "HEAD"]:
            return SHA
        if args == ["remote", "get-url", "origin"]:
            return source.REMOTE
        if args == ["config", "--local", "--get", "core.longpaths"]:
            return "true"
        if args == ["status", "--porcelain", "--untracked-files=all"]:
            return " M user-file" if dirty else ""
        if args == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return "HEAD"
        if args == ["checkout", "--detach", SHA]:
            return ""
        pytest.fail("unexpected Git operation")

    return git, calls


def test_new_short_namespace_persists_config_and_preserves_old_failed_clone(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old = tmp_path / ("reqsys-selfhost-source-" + SHA)
    old.mkdir()
    sentinel = old / "preserve.txt"
    sentinel.write_text("untouched", encoding="utf-8")
    git, calls = fake_git(tmp_path)
    monkeypatch.setattr(source, "ROOT", tmp_path)
    monkeypatch.setattr(source, "git", git)
    monkeypatch.setattr(source.socket, "gethostname", lambda: "DESKTOP-PDQK954")
    target = source.materialize(SHA)
    assert target == tmp_path / ("rs2-" + SHA)
    clone = next(args for args, _ in calls if args[0] == "clone")
    assert clone[:3] == ["clone", "--config", "core.longpaths=true"]
    assert "--no-checkout" in clone and source.REF in clone and source.REMOTE in clone
    assert ["checkout", "--detach", SHA] in [args for args, _ in calls]
    assert sentinel.read_text(encoding="utf-8") == "untouched"
    # Repetition validates the existing clean clone without checkout/reset/delete.
    assert source.materialize(SHA) == target
    assert sum(args[0] == "clone" for args, _ in calls) == 1
    assert sum(args[0] == "checkout" for args, _ in calls) == 1


def test_existing_edited_clone_fails_without_reset_or_delete(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / ("rs2-" + SHA)
    target.mkdir()
    (target / ".git").mkdir()
    sentinel = target / "user-file"
    sentinel.write_text("preserve", encoding="utf-8")
    git, calls = fake_git(tmp_path, dirty=True)
    monkeypatch.setattr(source, "ROOT", tmp_path)
    monkeypatch.setattr(source, "git", git)
    monkeypatch.setattr(source.socket, "gethostname", lambda: "DESKTOP-PDQK954")
    with pytest.raises(source.SourceError, match="SOURCE_TREE_NOT_CLEAN"):
        source.materialize(SHA)
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    assert not any(args[0] in {"clone", "checkout", "reset", "clean"} for args, _ in calls)


def test_wrong_host_and_bad_sha_do_not_create_source(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "not-created"
    monkeypatch.setattr(source, "ROOT", root)
    monkeypatch.setattr(source.socket, "gethostname", lambda: "other-host")
    with pytest.raises(source.SourceError, match="FIXED_HOST_MISMATCH"):
        source.materialize(SHA)
    monkeypatch.setattr(source.socket, "gethostname", lambda: "DESKTOP-PDQK954")
    with pytest.raises(source.SourceError, match="SOURCE_SHA_INVALID"):
        source.materialize("invalid")
    assert not root.exists()
