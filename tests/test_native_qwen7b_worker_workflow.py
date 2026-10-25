"""Static guard tests; real model evidence belongs to a separate physical job."""
from pathlib import Path

W = (Path(__file__).resolve().parents[1]
     / ".github" / "workflows" / "native-qwen7b-worker-e2e-dev.yml")


def workflow():
    return W.read_text(encoding="utf-8")


def test_native_worker_runs_only_on_approved_dispatch_or_exact_pr_transition():
    t = workflow()
    trigger = t.split("\npermissions:", 1)[0]
    assert "  workflow_dispatch:" in trigger
    assert "types: [edited]" in trigger
    assert "branches: [main]" in trigger
    assert "\n  push:" not in trigger and "\n  schedule:" not in trigger
    assert "types: [synchronize]" not in trigger
    assert "types: [ready_for_review]" not in trigger
    assert "head.repo.full_name == github.repository" in t
    assert "head.ref == 'test/native-qwen7b-git-eol-one-shot-20261024'" in t
    assert "github.event.pull_request.draft == true" in t
    assert "github.actor == 'ericson-j-santos'" in t
    assert t.count("github.event.action == 'edited'") == 1
    assert t.count("github.ref == 'refs/heads/main'") == 1
    assert "github.event.changes.body.from != null" in t
    assert "!contains(github.event.changes.body.from" in t
    assert "NATIVE_QWEN_INTEGRITY_20261024_7B_ONCE" in t


def test_exact_source_rules_host_and_governed_gateway():
    t = workflow()
    assert "WORKER_POOL_SHA: 4316e59831898c9081a10c95bf4809db6b20714f" in t
    assert "RULES_SHA: 6edb5990c777d487c41fb9ee48ccbf411b11d661" in t
    assert "NATIVE_MODEL_DIGEST_PREFIX: dae161e27b0e" in t
    assert 'NATIVE_OLLAMA_DEV: "1"' in t
    assert "self-hosted, Windows, X64, pc24x7, desktop-runtime, runtime-dev, desktop-pdqk954" in t
    assert '"DESKTOP-PDQK954"' in t
    assert "session_launcher.py" in t
    assert "SESSION_LAUNCH_OK" in t and "state_validated" in t
    assert "command_gateway.py" in t
    assert '"--risk", "2"' in t
    assert '"--expected-source-sha", $env:WORKER_POOL_SHA' in t
    assert "scripts\native_structured_worker_e2e.py" not in t  # no accidental newline in path
    assert "native_structured_worker_e2e.py" in t
    assert "pull_request.head.sha || github.sha" in t
    assert "persist-credentials: false" in t


def test_native_runner_uses_preinstalled_windows_powershell_not_missing_pwsh():
    source = workflow().split("\n  physical_runner_watchdog:", 1)[0]
    assert source.count("shell: powershell") == 5
    assert "shell: pwsh" not in source
    assert 'if ($env:COMPUTERNAME -ne "DESKTOP-PDQK954")' in source


def test_fail_closed_watchdog_and_no_extra_execution():
    t = workflow()
    assert "physical_runner_watchdog:" in t
    assert "Physical runner queue watchdog" in t
    assert "TARGET_JOB_NAME: Native Qwen 7B code repair E2E on Desktop" in t
    assert 'STALL_AFTER_SECONDS: "60"' in t
    assert "cancelWorkflowRun" in t
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in t
    assert 'timeout-minutes: 11' in t
    assert '"--timeout", "490"' in t
    assert "docker run" not in t.lower()
    assert "docker exec" not in t.lower()
    assert "secrets." not in t
    assert "actions: write" in t  # watchdog only


def test_admission_checks_exact_shas_and_executed_ci_before_physical_job():
    t = workflow()
    assert "  admission:" in t
    assert "Native E2E immutable check admission" in t
    assert t.count("needs: admission") == 2
    assert t.count("if: needs.admission.result == 'success'") == 2
    assert "github.rest.checks.listForRef" in t
    assert "PR_CURRENT_STATE_CHANGED" in t
    assert "PR_MAIN_SHA_CHANGED" in t
    assert "WORKER_REQUIRED_CHECK_NOT_EXECUTED_" in t
    assert "DESKTOP_REQUIRED_CHECK_NOT_EXECUTED_" in t
    assert "x.status === 'completed' && x.conclusion === 'success'" in t



def assert_governed_native_venv(t: str) -> None:
    """Pinned dependencies must be isolated and all writes governed."""
    assert "Create isolated native Python venv through Gateway" in t
    assert "Install pinned Worker Pool test dependencies in venv via Gateway" in t
    assert 'Join-Path $env:TARGET_PATH ".venv"' in t
    assert 'Join-Path $env:TARGET_PATH ".venv\\Scripts\\python.exe"' in t
    assert '"python", "-m", "venv", $venv' in t
    assert '$nativePython, "-m", "pip", "install"' in t
    assert '"--isolated", "--disable-pip-version-check", "--no-input"' in t
    assert '"--no-cache-dir", "-r", $requirements' in t
    assert '$nativePython, "-m", "pip", "check"' in t
    assert '$nativePython, $worker,' in t
    assert t.count('"--risk", "2"') == 3
    assert t.count('"--risk", "1"') == 1
    assert "--break-system-packages" not in t
    assert "--system-site-packages" not in t
    assert "pip install --user" not in t
    assert "docker run" not in t.lower()
    assert "docker exec" not in t.lower()


def test_governed_native_venv_and_pinned_dependency_install():
    assert_governed_native_venv(workflow())


def test_native_venv_rejects_unsafe_regressions():
    import pytest
    s = workflow()
    for before, after in [
        ('"--isolated", "--disable-pip-version-check", "--no-input"', '"--disable-pip-version-check", "--no-input"'),
        ('"python", "-m", "venv", $venv', '"python", "-m", "pip", "install"'),
        ('$nativePython, $worker,', '"python", $worker,'),
        ('"--no-cache-dir", "-r", $requirements', '"--no-cache-dir", "pytest"'),
    ]:
        assert before in s
        with pytest.raises(AssertionError):
            assert_governed_native_venv(s.replace(before, after, 1))
