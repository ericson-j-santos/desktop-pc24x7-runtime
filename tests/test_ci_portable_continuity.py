"""Keep deterministic development independent from a named physical executor."""
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]


def assert_portable_ci(text: str) -> None:
    """Check the deliberately small CI contract, not arbitrary YAML syntax."""
    text = text.replace("\r\n", "\n")
    assert re.search(r"^  push:\n", text, re.M)
    assert re.search(r"^  pull_request:\s*$", text, re.M)
    assert re.search(r"^  contents: read\s*$", text, re.M)
    assert re.search(r"^    runs-on: \$\{\{ matrix\.os \}\}\s*$", text, re.M)
    assert re.findall(r"^          - os: (\S+)\s*$", text, re.M) == [
        "windows-latest", "ubuntu-latest"
    ]
    assert "check_name: Python compile and tests" in text
    assert "check_name: Portable Linux compile and tests" in text
    assert "fail-fast: false" in text
    assert "timeout-minutes: 10" in text
    assert "persist-credentials: false" in text
    assert "run: git rev-parse HEAD" in text
    assert "run: python -m compileall -q scripts tests" in text
    assert re.search(r"^        run: python -m pytest -ra\s*$", text, re.M)
    assert "node --test tests/test_reqsys_dev_inventory_admission.cjs tests/test_reqsys_dev_inventory_pickup_watchdog.cjs" in text
    assert text.count("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }") == 3
    for forbidden in (
        "self-hosted", "DESKTOP-", "Noteri", "continue-on-error",
        "workflow_dispatch", "secrets.", "FRESH_DEDICATED_CANARY_REQUIRED",
    ):
        assert forbidden not in text
    assert not re.search(r"^\s+(needs|if):", text, re.M)
    assert not re.search(r"^\s+(paths|paths-ignore):", text, re.M)


def test_ci_is_hosted_and_does_not_wait_for_physical_admission():
    assert_portable_ci((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("old,new", [
    ("- os: ubuntu-latest", "- os: self-hosted"),
    ("    timeout-minutes: 10", "    needs: admission\n    timeout-minutes: 10"),
    ("    timeout-minutes: 10", "    if: false\n    timeout-minutes: 10"),
    ("fail-fast: false", "fail-fast: true"),
    ("persist-credentials: false", "persist-credentials: true"),
    ("run: python -m pytest -ra", "run: python -m pytest -ra --ignore=tests"),
    ("run: python -m pytest -ra", "run: echo success"),
    ("node --test tests/test_reqsys_dev_inventory_admission.cjs tests/test_reqsys_dev_inventory_pickup_watchdog.cjs",
     "node --check scripts/reqsys_dev_inventory_admission.cjs"),
    ("  contents: read", "  contents: write"),
])
def test_regression_rejects_host_affinity_suppressed_tests_or_writes(old, new):
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert_portable_ci(source)
    assert old in source
    with pytest.raises(AssertionError):
        assert_portable_ci(source.replace(old, new, 1))


def test_ci_contract_handles_windows_and_unix_line_endings():
    source = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert_portable_ci(source)
    assert_portable_ci(source.replace("\n", "\r\n"))
    assert_portable_ci(source)


def test_physical_inventory_remains_a_separate_fail_closed_workflow():
    source = (ROOT / ".github/workflows/reqsys-dev-readonly-inventory.yml").read_text(encoding="utf-8")
    assert "runs-on: [self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev, desktop-pdqk954]" in source
    assert source.count("needs.admission.outputs.physical_ready == 'true'") == 2
    assert source.count("needs.admission.outputs.admitted_attempt == github.run_attempt") == 2
    assert "SESSION_LAUNCH_OK" in source
    assert "--require-runner-version-preflight" in source
    assert "continue-on-error" not in source
