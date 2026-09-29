from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "dedicated_runner_e2e.py"
SPEC = importlib.util.spec_from_file_location("dedicated_runner_e2e", MODULE)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def set_valid_environment(monkeypatch) -> None:
    monkeypatch.setattr(m.socket, "gethostname", lambda: m.EXPECTED_HOST)
    monkeypatch.setenv("GITHUB_REPOSITORY", m.EXPECTED_REPOSITORY)
    monkeypatch.setenv("RUNNER_NAME", m.EXPECTED_RUNNER)
    monkeypatch.setenv("RUNNER_OS", "Windows")
    monkeypatch.setenv("RUNNER_ARCH", "X64")
    monkeypatch.setenv("GITHUB_SHA", "c" * 40)
    monkeypatch.setenv("RULES_SHA", "e" * 40)
    monkeypatch.setenv("RUNNER_VERSION_OBSERVED", "2.337.0")
    monkeypatch.setenv("RUNNER_REGISTRATION_SUPPORTED", "true")
    monkeypatch.setenv("RUNNER_RUNTIME_SUPPORTED", "true")
    monkeypatch.setenv("RUNNER_DEPRECATION_API_STATUS", "http_403")


def test_positive_contract(monkeypatch) -> None:
    set_valid_environment(monkeypatch)
    evidence = m.build_evidence()
    assert evidence["ok"] is True
    assert evidence["runner_version"] == "2.337.0"
    assert evidence["rules_sha"] == "e" * 40


def test_wrong_runner_fails(monkeypatch) -> None:
    set_valid_environment(monkeypatch)
    monkeypatch.setenv("RUNNER_NAME", "DESKTOP-PDQK954")
    assert m.build_evidence()["ok"] is False


def test_missing_runner_version_fails(monkeypatch) -> None:
    set_valid_environment(monkeypatch)
    monkeypatch.delenv("RUNNER_VERSION_OBSERVED")
    assert m.build_evidence()["ok"] is False


def test_unsupported_runtime_flag_fails(monkeypatch) -> None:
    set_valid_environment(monkeypatch)
    monkeypatch.setenv("RUNNER_RUNTIME_SUPPORTED", "false")
    assert m.build_evidence()["ok"] is False
