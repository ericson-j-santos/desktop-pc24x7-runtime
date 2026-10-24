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
    assert "types: [ready_for_review]" in trigger
    assert "branches: [main]" in trigger
    assert "\n  push:" not in trigger and "\n  schedule:" not in trigger
    assert "types: [synchronize]" not in trigger
    assert "head.repo.full_name == github.repository" in t
    assert "head.ref == 'feat/native-qwen7b-worker-e2e-20261024'" in t
    assert t.count("github.event.action == 'ready_for_review'") == 2
    assert t.count("github.ref == 'refs/heads/main'") == 2


def test_exact_source_rules_host_and_governed_gateway():
    t = workflow()
    assert "WORKER_POOL_SHA: 34fcbe54ff6cf22877d2828d42dbf40eeffeca45" in t
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
    assert source.count("shell: powershell") == 3
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
