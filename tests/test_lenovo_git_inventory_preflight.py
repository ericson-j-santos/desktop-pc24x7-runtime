"""Regressão da falha física #43793281463: nada executa Git pré-bootstrap.

O Git ausente é um bloqueio operacional, não justificativa para executar
programas encontrados em caminhos não autenticados. Checkout transitório não
concede autorização ao Gateway.
"""
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/lenovo-installed-inventory-readonly.yml"
SPEC = yaml.load(WORKFLOW.read_text("utf-8"), Loader=yaml.BaseLoader)
ADMIT = SPEC["jobs"]["admit"]
INVENTORY = SPEC["jobs"]["inventory"]


def test_git_prebootstrap_invocation_removed_and_no_fallback():
    assert ADMIT["runs-on"] == "ubuntu-latest"
    assert "REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA == github.sha" in ADMIT["if"]
    assert INVENTORY["needs"] == "admit"
    assert INVENTORY["if"] == "needs.admit.result == 'success'"
    steps = INVENTORY["steps"]
    assert [step["name"] for step in steps] == [
        "Checkout exact source without credentials",
        "Checkout canonical rules without credentials",
        "Bootstrap governed physical session",
        "Read installed SHA and digests through Command Gateway Risk 1",
    ]
    assert all("run" not in step and "shell" not in step for step in steps[:2])
    assert all(step["with"]["persist-credentials"] == "false" for step in steps[:2])
    assert "['bootstrap']()" in steps[2]["run"]
    assert "'--risk','1'" in steps[3]["run"]
    assert "'--expected-head',sha" in steps[3]["run"]
    full = WORKFLOW.read_text("utf-8")
    for forbidden in ("Resolve fixed existing Git client", "git.exe", "GITHUB_PATH",
                      "LENOVO_GIT_PREFLIGHT_MISSING", "LENOVO_GIT_CLIENT_UNAVAILABLE",
                      "ProgramFiles", "winget", "choco", "Invoke-WebRequest"):
        assert forbidden not in full


def test_hosted_admission_requires_exact_owner_first_attempt_main_and_ci():
    source = ADMIT["steps"][0]["with"]["script"]
    for key in ("GITHUB_RUN_ATTEMPT", "context.actor", "context.sha", "context.ref",
                "main.commit.sha", "LENOVO_INVENTORY_CI_GATES_REQUIRED",
                "LENOVO_INVENTORY_EXACT_CI_REQUIRED", "core.setOutput('rules_sha'"):
        assert key in source
    assert ADMIT["steps"][0]["uses"] == (
        "actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea"
    )
    assert ADMIT["outputs"]["rules_sha"] == "${{ steps.admit.outputs.rules_sha }}"
    assert INVENTORY["steps"][1]["with"]["ref"] == "${{ needs.admit.outputs.rules_sha }}"


def test_no_physical_inventory_without_successful_session():
    steps = INVENTORY["steps"]
    bootstrap = steps[2]
    inventory = steps[3]
    assert bootstrap["id"] == "session"
    assert "['bootstrap']()" in bootstrap["run"]
    assert inventory["env"]["SESSION_ID"] == "${{ steps.session.outputs.session_id }}"
    assert inventory["env"]["TARGET_PATH"] == "${{ steps.session.outputs.target_path }}"
    assert inventory["env"]["ANCHOR_SHA"] == "${{ steps.session.outputs.anchor_sha }}"
    assert "lenovo_control_plane_installed_inventory.py" in inventory["run"]
    assert "LENOVO_INVENTORY_GATEWAY_BLOCKED" in inventory["run"]
    assert "LENOVO_INVENTORY_RECEIPT_REJECTED" in inventory["run"]
