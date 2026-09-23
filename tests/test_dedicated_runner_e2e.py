from __future__ import annotations
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "dedicated_runner_e2e.py"
SPEC = importlib.util.spec_from_file_location("dedicated_runner_e2e", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def test_positive_contract(monkeypatch) -> None:
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.EXPECTED_HOST)
    monkeypatch.setenv("GITHUB_REPOSITORY", m.EXPECTED_REPOSITORY)
    monkeypatch.setenv("RUNNER_NAME", m.EXPECTED_RUNNER)
    monkeypatch.setenv("RUNNER_OS", "Windows")
    monkeypatch.setenv("RUNNER_ARCH", "X64")
    monkeypatch.setenv("GITHUB_SHA", "c" * 40)
    assert m.build_evidence()["ok"] is True


def test_wrong_runner_fails(monkeypatch) -> None:
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.EXPECTED_HOST)
    monkeypatch.setenv("GITHUB_REPOSITORY", m.EXPECTED_REPOSITORY)
    monkeypatch.setenv("RUNNER_NAME", "DESKTOP-PDQK954")
    monkeypatch.setenv("RUNNER_OS", "Windows")
    monkeypatch.setenv("RUNNER_ARCH", "X64")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    assert m.build_evidence()["ok"] is False
