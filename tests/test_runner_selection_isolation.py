from __future__ import annotations

import re
from pathlib import Path

import importlib.util
import sys


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "scripts" / "pc24x7_host_policy.py"
SPEC = importlib.util.spec_from_file_location("pc24x7_host_policy_isolation_tested", POLICY)
assert SPEC and SPEC.loader
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


RUNS_ON = re.compile(r"^\s*runs-on:\s*\[(?P<labels>[^]]+)\]\s*$")


def _self_hosted_selectors() -> list[tuple[Path, set[str]]]:
    selectors: list[tuple[Path, set[str]]] = []
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            match = RUNS_ON.match(line)
            if not match:
                continue
            labels = {item.strip() for item in match.group("labels").split(",")}
            if {"self-hosted", "Windows", "X64"}.issubset(labels):
                selectors.append((workflow, labels))
    return selectors


def test_desktop_runtime_workflows_require_a_host_specific_label() -> None:
    selectors = _self_hosted_selectors()
    assert selectors
    secondary = []
    for workflow, labels in selectors:
        if "noteri" in labels:
            continue
        assert "pc24x7" in labels, workflow.name
        if "desktop-rp23ogs" in labels:
            secondary.append((workflow, labels))
            assert workflow.name == "dedicated-runtime-runner-e2e.yml"
            assert "desktop-pdqk954" not in labels
            continue
        assert "desktop-pdqk954" in labels, f"generic or RP23OGS-ambiguous selector: {workflow.name}: {labels}"
    assert len(secondary) == 1


def test_no_generic_windows_self_hosted_selector_remains() -> None:
    for workflow, labels in _self_hosted_selectors():
        assert labels - {"self-hosted", "Windows", "X64"}, f"generic selector: {workflow.name}"


def test_profile_labels_match_scheduler_isolation_contract() -> None:
    primary = policy.authorized_host("DESKTOP-PDQK954")
    secondary = policy.authorized_host("DESKTOP-RP23OGS")
    primary_labels = set(primary.runner_labels.split(","))
    secondary_labels = set(secondary.runner_labels.split(","))

    assert "desktop-pdqk954" in primary_labels
    assert "desktop-rp23ogs" in secondary_labels
    assert primary_labels.isdisjoint({"desktop-rp23ogs"})
    assert secondary_labels.isdisjoint({"desktop-pdqk954"})
