from __future__ import annotations

from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "dedicated-runtime-runner-e2e.yml"
)


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_canary_is_manual_and_gated_by_canonical_rules() -> None:
    raw = workflow_text()
    trigger_block = raw.split("\npermissions:", 1)[0]
    assert "workflow_dispatch:" in trigger_block
    assert "\n  push:" not in trigger_block
    assert "Resolve main SHA and require rules 1.6.9+" in raw
    assert "RULES_1_6_9_REQUIRED" in raw
    assert "chatgpt-operational-rules" in raw


def test_canary_bootstraps_before_gateway_execution() -> None:
    raw = workflow_text()
    bootstrap = raw.index("Bootstrap governed session and runner version preflight")
    gateway = raw.index("Prove exact host, repository, runner and version through Command Gateway")
    assert bootstrap < gateway
    assert "--require-runner-version-preflight" in raw
    assert "SESSION_LAUNCH_OK" in raw
    assert "RUNNER_VERSION_PREFLIGHT_BLOCKED" in raw
    assert "command_gateway.py" in raw
    assert "scripts\\dedicated_runner_e2e.py" in raw


def test_canary_persists_runner_version_contract() -> None:
    raw = workflow_text()
    assert "RUNNER_VERSION_OBSERVED" in raw
    assert "RUNNER_REGISTRATION_SUPPORTED" in raw
    assert "RUNNER_RUNTIME_SUPPORTED" in raw
    assert "RUNNER_DEPRECATION_API_STATUS" in raw


def test_canary_queue_is_bounded_fail_closed() -> None:
    raw = workflow_text()
    assert "name: Dedicated runner queue watchdog" in raw
    assert 'STALL_AFTER_SECONDS: "300"' in raw
    assert "progress_watchdog.py" in raw
    assert "actions: write" in raw
    assert "cancelWorkflowRun" in raw
    assert "SELF_HOSTED_RUNNER_UNAVAILABLE" in raw


def test_lenovo_pickup_is_exact_sha_host_runner_and_receipt_bound() -> None:
    raw = workflow_text()
    lenovo = raw.split("\n  lenovo_pickup:\n", 1)[1].split("\n  lenovo_readback:\n", 1)[0]
    assert "lenovo_control_plane_pickup:" in raw
    assert "inputs.lenovo_control_plane_pickup == true" in raw
    assert "inputs.diagnostic == 'runner-identity'" in raw
    assert "Pickup on Lenovo free control plane" in raw
    assert "desktop-rp23ogs" in raw
    assert "DESKTOP-RP23OGS-runtime" in raw
    assert lenovo.count("shell: python") == 2
    assert "shell: powershell" not in lenovo
    assert "shell: cmd" not in lenovo
    assert lenovo.count("runpy.run_path") == 2
    assert lenovo.count('os.environ["GITHUB_WORKSPACE"]') == 2
    assert 'module["bootstrap"]()' in lenovo
    assert 'module["prove"]()' in lenovo
    assert "lenovo-control-plane-pickup" in raw
    assert 'module["emit_receipt"]()' in lenovo
    assert "actions/upload-artifact@" not in lenovo
    assert "steps.lenovo_proof.outputs.receipt_sha256" in lenovo
    assert "process.env.EXPECTED_RUNNER" in raw


def test_lenovo_independent_readback_checks_job_outputs_and_real_runner() -> None:
    raw = workflow_text()
    readback = raw.split("\n  lenovo_readback:\n", 1)[1].split("\n  queue_watchdog:\n", 1)[0]
    assert "needs: [resolve_rules, lenovo_pickup]" in readback
    assert "runs-on: ubuntu-latest" in readback
    assert "needs.lenovo_pickup.outputs.receipt_b64" in readback
    assert "needs.lenovo_pickup.outputs.receipt_sha256" in readback
    assert "base64 --decode" in readback and "sha256sum" in readback
    assert "LENOVO_RECEIPT_SHA256_VERIFIED" in readback
    assert "LENOVO_INDEPENDENT_READBACK_OK" in readback
    assert "gh api" in readback and "runner_id" in readback
    assert "Prove Lenovo control-plane pickup through Command Gateway" in readback
    assert "Bootstrap governed Lenovo session and runner version preflight" in readback
    assert "actions/upload-artifact@" not in readback
    assert "actions/download-artifact@" not in readback
    assert "synthetic_test_only" not in readback
