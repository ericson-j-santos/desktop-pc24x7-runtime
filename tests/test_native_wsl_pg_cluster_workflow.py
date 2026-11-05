"""Protects native physical E2E gating for Issue #134 without dispatching a host."""
from __future__ import annotations

from pathlib import Path
import yaml
import pytest

WORKFLOW = Path(__file__).parents[1] / '.github/workflows/dedicated-runtime-runner-e2e.yml'
DIAGNOSTIC = 'native-wsl-postgres-cluster-readonly'
SCRIPT = 'native_wsl_pg_cluster_probe.py'


def load(text: str):
    return yaml.load(text, Loader=yaml.BaseLoader)


def step(jobs, name: str):
    for job in jobs.values():
        for current in job.get('steps', []):
            if current.get('name') == name:
                return current
    raise AssertionError('required step missing: ' + name)


def guarded(workflow: dict) -> None:
    option = workflow['on']['workflow_dispatch']['inputs']['diagnostic']['options']
    assert option.count(DIAGNOSTIC) == 1
    assert not workflow['on'].get('pull_request')  # Physical acquisition only on owner manual dispatch.
    assert 'self-hosted' in workflow['jobs']['e2e']['runs-on']
    assert 'desktop-pdqk954' in workflow['jobs']['e2e']['runs-on']
    admit = step(workflow['jobs'], 'Admit fixed inventory from reviewed current main and successful native CI')
    code = admit['with']['script']
    assert DIAGNOSTIC in admit['if']
    for token in ("context.actor !== 'ericson-j-santos'", "context.ref !== 'refs/heads/main'", "GITHUB_RUN_ATTEMPT !== '1'", "INVENTORY_SOURCE_SHA !== context.sha", "NATIVE_INVENTORY_EXACT_SHA_CI_REQUIRED"):
        assert token in code
    stale = step(workflow['jobs'], 'Reject stale native pickup before checkout or bootstrap')
    assert DIAGNOSTIC in stale['if']
    assert 'age > 300000' in stale['with']['script']
    assert 'DESKTOP-PDQK954' in stale['with']['script']
    session = step(workflow['jobs'], 'Bootstrap governed session and runner version preflight')
    run = session['run']
    for token in ('session_launcher.py', 'SESSION_LAUNCH_OK', 'state_validated', '--expected-head', '--require-runner-version-preflight'):
        assert token in run
    physical = step(workflow['jobs'], 'Probe PostgreSQL 15/main cluster read-only through Command Gateway')
    assert physical['if'].strip() == f"inputs.diagnostic == '{DIAGNOSTIC}'"
    cmd = physical['run']
    for token in ('command_gateway.py','--expected-head','--session-id','--risk', '"1"', '"python", "-B", $script', SCRIPT):
        assert token in cmd
    assert 'shell=True' not in cmd and 'systemctl restart' not in cmd and 'docker' not in cmd
    assert physical['env'].get('INVENTORY_SESSION_VALIDATED') == 'true'
    for name in ('Report expired native pickup without cancellation','Fail closed and cancel stalled canary'):
        assert DIAGNOSTIC in step(workflow['jobs'],name)['if']
    assert DIAGNOSTIC in workflow['concurrency']['group']
    assert DIAGNOSTIC in workflow['concurrency']['cancel-in-progress']
    for name in ('Prove exact host, repository, runner and version through Command Gateway','Upload sanitized evidence'):
        assert DIAGNOSTIC in step(workflow['jobs'],name)['if']


def test_guarded_workflow_after_change():
    guarded(load(WORKFLOW.read_text(encoding='utf-8')))


def test_reject_unlisted_diagnostic():
    s=WORKFLOW.read_text(encoding='utf-8').replace('native-wsl-postgres-cluster-readonly, orchestrator-runner-preflight', 'orchestrator-runner-preflight')
    with pytest.raises(AssertionError):
        guarded(load(s))


def test_reject_missing_expected_sha():
    s=WORKFLOW.read_text(encoding='utf-8')
    # mutate specifically the new step, not another diagnostic
    from_marker=s.index('Probe PostgreSQL 15/main cluster read-only through Command Gateway')
    pre=s[:from_marker]
    new=s[from_marker:].replace('"--expected-head", $env:ANCHOR_SHA,', '"--allow-unpinned", "true",', 1)
    with pytest.raises(AssertionError):
        guarded(load(pre+new))


def test_reject_non_owner_manual_admission():
    s=WORKFLOW.read_text(encoding='utf-8')
    from_marker=s.index("- name: Admit fixed inventory from reviewed current main and successful native CI")
    before=s[:from_marker]
    after=s[from_marker:].replace("context.actor !== 'ericson-j-santos'", "context.actor !== 'anonymous'", 1)
    with pytest.raises(AssertionError):
        guarded(load(before+after))


def test_reject_missing_session_validation():
    s=WORKFLOW.read_text(encoding='utf-8').replace('SESSION_LAUNCH_OK', 'SESSION_LAUNCH_UNKNOWN', 1)
    with pytest.raises(AssertionError):
        guarded(load(s))


def test_reject_precondition_without_main_only():
    s=WORKFLOW.read_text(encoding='utf-8').replace("context.ref !== 'refs/heads/main'", "context.ref !== 'refs/heads/feat'", 1)
    with pytest.raises(AssertionError):
        guarded(load(s))
