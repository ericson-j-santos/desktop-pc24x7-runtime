"""Fail-closed regression checks for artifact-free GitHub job outputs."""
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
TRANSPORT = ROOT / ".github/workflows/lenovo-job-output-transport-ci.yml"


def _transport() -> str:
    return TRANSPORT.read_text(encoding="utf-8")


def test_portable_main_ci_remains_without_cross_job_or_physical_dependencies() -> None:
    source = CI.read_text(encoding="utf-8")
    assert "lenovo_output_producer:" not in source
    assert "lenovo_output_readback:" not in source
    assert not re.search(r"^\\s+(needs|if):", source, re.M)
    assert "self-hosted" not in source


def test_transport_is_hosted_nonmutating_and_artifact_free() -> None:
    source = _transport()
    assert "pull_request:" in source
    assert source.count("runs-on: ubuntu-latest") == 2
    assert "needs: lenovo_output_producer" in source
    assert "needs.lenovo_output_producer.outputs.receipt_b64" in source
    assert "steps.emit.outputs.receipt_sha256" in source
    assert "SYNTHETIC_CROSS_JOB_TRANSPORT_OK" in source
    for forbidden in ("self-hosted", "workflow_dispatch", "actions/upload-artifact",
                      "actions/download-artifact", "secrets.", "actions: write"):
        assert forbidden not in source


def test_receipt_controls_share_verifier_including_malformed_base64() -> None:
    source = _transport()
    assert "verify_transport()" in source
    assert "expect_rejected()" in source
    assert "base64 --decode" in source
    assert "sha256sum" in source
    assert 'wc -c)" -le 12000' in source
    assert 'wc -c < _receipt_transport/checked.json)" -le 8192' in source
    for case in ("hash", "sha", "run", "attempt", "missing", "size", "base64"):
        assert f"expect_rejected {case} " in source
    assert 'expect_rejected base64 "%%%"' in source
    assert "printf '%%%' | base64" not in source
    assert "source_sha == $sha" in source
    assert "run_attempt == $attempt" in source


@pytest.mark.parametrize("bad", ["self-hosted", "actions/upload-artifact", "workflow_dispatch"])
def test_regression_detects_forbidden_transport_backend(bad: str) -> None:
    content = _transport() + "\n" + bad
    with pytest.raises(AssertionError):
        for forbidden in ("self-hosted", "actions/upload-artifact", "workflow_dispatch"):
            assert forbidden not in content
