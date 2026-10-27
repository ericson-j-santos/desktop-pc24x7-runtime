from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import bootstrap_dedicated_runtime_runner as bootstrap
import orchestrator_dev_runner_preflight as probe
import pc24x7_host_policy as policy

SHA = "a" * 40
CORRELATION = "orchestrator-bootstrap-test"
DIGEST = "b" * 64


@pytest.fixture
def plan_environment(monkeypatch, tmp_path):
    home = tmp_path / "EngineeringOrchestratorDEV" / "GitHubRunner"
    readback = {
        "runner_home": str(home),
        "registration_required": True,
        "observed_runner_id": None,
    }
    monkeypatch.setattr(bootstrap, "_orchestrator_readback", lambda *args: dict(readback))
    monkeypatch.setattr(bootstrap, "validate_host", lambda: "DESKTOP-PDQK954")
    monkeypatch.setattr(bootstrap, "_orchestrator_package_policy", lambda: {
        "selected_version": policy.ORCHESTRATOR_DEV_RUNNER_PACKAGE["version"],
        "official_package_metadata_verified": True,
        "registration_version_supported": True,
        "deprecation_api_status": "ok",
        "registration_deprecates_at": None,
        "runtime_deprecates_at": None,
    })
    return home, readback


def test_plan_replays_without_writes_downloads_tokens_or_listener(
    plan_environment, monkeypatch, tmp_path,
):
    def forbidden(*args, **kwargs):
        pytest.fail("read-only plan attempted an effect")

    for name in (
        "_orchestrator_download_package", "_orchestrator_registration_token",
        "_orchestrator_configure", "persist", "ensure_runner_binaries",
        "register_runner",
    ):
        monkeypatch.setattr(bootstrap, name, forbidden)
    monkeypatch.setattr(bootstrap.watchdog, "start_runner", forbidden)
    before = sorted(str(path) for path in tmp_path.rglob("*"))
    legacy = (bootstrap.REPOSITORY, bootstrap.RUNNER_NAME, bootstrap.RUNNER_LABELS)
    first = bootstrap.orchestrator_dev_plan(source_sha=SHA, correlation_id=CORRELATION)
    second = bootstrap.orchestrator_dev_plan(source_sha=SHA, correlation_id=CORRELATION)
    assert first == second
    assert first["read_only"] is True
    assert first["registration_token_requested"] is False
    assert first["runner_binary_version_proven"] is False
    assert first["physical_pickup_proven"] is False
    assert first["additional_cost_authorized_brl"] == 0
    assert sorted(str(path) for path in tmp_path.rglob("*")) == before
    assert (bootstrap.REPOSITORY, bootstrap.RUNNER_NAME, bootstrap.RUNNER_LABELS) == legacy
    assert not plan_environment[0].exists()


@pytest.mark.parametrize("field,value", [
    ("runner_home", "/different/planned/home"),
    ("observed_runner_id", 57),
    ("registration_required", False),
])
def test_plan_digest_binds_observed_target_state(plan_environment, field, value):
    _, readback = plan_environment
    before = bootstrap.orchestrator_dev_plan(source_sha=SHA, correlation_id=CORRELATION)
    readback[field] = value
    after = bootstrap.orchestrator_dev_plan(source_sha=SHA, correlation_id=CORRELATION)
    assert before["plan_sha256"] != after["plan_sha256"]


def test_plan_digest_binds_source_and_correlation(plan_environment):
    first = bootstrap.orchestrator_dev_plan(source_sha=SHA, correlation_id=CORRELATION)
    assert bootstrap.orchestrator_dev_plan(
        source_sha="c" * 40, correlation_id=CORRELATION,
    )["plan_sha256"] != first["plan_sha256"]
    assert bootstrap.orchestrator_dev_plan(
        source_sha=SHA, correlation_id=CORRELATION + "-next",
    )["plan_sha256"] != first["plan_sha256"]


def official_release():
    package = policy.ORCHESTRATOR_DEV_RUNNER_PACKAGE
    return {
        "tag_name": "v" + package["version"],
        "draft": False,
        "prerelease": False,
        "assets": [{
            "name": package["filename"],
            "size": package["size"],
            "digest": "sha256:" + package["sha256"],
            "browser_download_url": package["url"],
        }],
    }


def version_policy():
    return {
        "runner_version": policy.ORCHESTRATOR_DEV_RUNNER_PACKAGE["version"],
        "registration_deprecates_at": None,
        "runtime_deprecates_at": None,
    }


def test_version_policy_uses_only_two_fixed_gets(monkeypatch):
    seen = []

    def api(path, *, method="GET"):
        seen.append((method, path))
        return official_release() if "/releases/tags/" in path else version_policy()

    monkeypatch.setattr(bootstrap, "local_gh_api_json", api)
    result = bootstrap._orchestrator_package_policy()
    assert result["registration_version_supported"] is True
    assert seen == [
        ("GET", "/repos/actions/runner/releases/tags/v2.338.2"),
        ("GET", "/repos/ericson-j-santos/reqsys-engineering-orchestrator/actions/runners/deprecations/2.338.2"),
    ]


@pytest.mark.parametrize("change", [
    "draft", "prerelease", "duplicate_asset", "size", "digest", "url",
])
def test_package_metadata_drift_blocks_before_download(monkeypatch, change):
    release = official_release()
    if change in {"draft", "prerelease"}:
        release[change] = True
    elif change == "duplicate_asset":
        release["assets"].append(dict(release["assets"][0]))
    elif change == "size":
        release["assets"][0]["size"] += 1
    elif change == "digest":
        release["assets"][0]["digest"] = "sha256:" + "0" * 64
    else:
        release["assets"][0]["browser_download_url"] = "https://example.invalid/runner.zip"
    monkeypatch.setattr(bootstrap, "local_gh_api_json", lambda *args, **kwargs: release)
    with pytest.raises(bootstrap.BootstrapError) as error:
        bootstrap._orchestrator_package_policy()
    assert error.value.state == "orchestrator_package_metadata_mismatch"


@pytest.mark.parametrize("field,value", [
    ("runner_version", "2.337.0"),
    ("registration_deprecates_at", "2000-01-01T00:00:00Z"),
    ("runtime_deprecates_at", "2000-01-01T00:00:00Z"),
    ("registration_deprecates_at", "2100-01-01T00:00:00"),
    ("runtime_deprecates_at", True),
])
def test_version_policy_rejects_wrong_expired_or_invalid_values(monkeypatch, field, value):
    schedule = version_policy()
    schedule[field] = value
    monkeypatch.setattr(
        bootstrap, "local_gh_api_json",
        lambda path, **kwargs: official_release() if "/releases/tags/" in path else schedule,
    )
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap._orchestrator_package_policy()


def test_version_policy_missing_field_fails_closed(monkeypatch):
    schedule = version_policy()
    schedule.pop("runtime_deprecates_at")
    monkeypatch.setattr(
        bootstrap, "local_gh_api_json",
        lambda path, **kwargs: official_release() if "/releases/tags/" in path else schedule,
    )
    with pytest.raises(bootstrap.BootstrapError) as error:
        bootstrap._orchestrator_package_policy()
    assert error.value.state == "orchestrator_version_policy_incomplete"


def zip_package(monkeypatch, *, escape=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in ("config.cmd", "run.cmd", "bin/Runner.Listener.exe"):
            archive.writestr(name, "synthetic-test-file")
        if escape:
            archive.writestr("../escaped.txt", "must-not-escape")
    raw = buffer.getvalue()
    package = dict(policy.ORCHESTRATOR_DEV_RUNNER_PACKAGE)
    package.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(policy, "ORCHESTRATOR_DEV_RUNNER_PACKAGE", MappingProxyType(package))
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(raw))
    return package


def test_download_verifies_bytes_and_extracts_fixed_contract(monkeypatch, tmp_path):
    zip_package(monkeypatch)
    result = bootstrap._orchestrator_download_package(tmp_path)
    assert result == tmp_path / "package"
    assert bootstrap.runner_binary_contract(result)
    assert not (result / ".runner").exists()


@pytest.mark.parametrize("bad", ["size", "digest"])
def test_invalid_download_never_extracts(monkeypatch, tmp_path, bad):
    package = zip_package(monkeypatch)
    package[bad if bad == "size" else "sha256"] = (
        package["size"] - 1 if bad == "size" else "0" * 64
    )
    monkeypatch.setattr(policy, "ORCHESTRATOR_DEV_RUNNER_PACKAGE", MappingProxyType(package))
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap._orchestrator_download_package(tmp_path)
    assert not (tmp_path / "package").exists()


def test_verified_zip_still_cannot_escape_staging(monkeypatch, tmp_path):
    zip_package(monkeypatch, escape=True)
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap._orchestrator_download_package(tmp_path)
    assert not (tmp_path / "escaped.txt").exists()


@pytest.mark.parametrize("code,output", [
    (1, "2.338.2"), (0, "2.337.0"), (0, "garbage"), (0, "2.338.2\nextra"),
])
def test_binary_version_gate_rejects_bad_process_result(monkeypatch, tmp_path, code, output):
    monkeypatch.setattr(
        bootstrap.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=code, stdout=output),
    )
    with pytest.raises(bootstrap.BootstrapError) as error:
        bootstrap._orchestrator_version_probe(tmp_path)
    assert error.value.state == "orchestrator_runner_binary_version_mismatch"



@pytest.fixture
def apply_environment(monkeypatch, tmp_path):
    home = tmp_path / "EngineeringOrchestratorDEV" / "GitHubRunner"
    home.parent.mkdir()
    state = {"registered": False, "calls": []}
    plan = {
        "plan_sha256": DIGEST, "runner_home": str(home),
        "registration_required": True, "observed_runner_id": None,
    }

    def current_plan(**kwargs):
        if state["registered"]:
            return {**plan, "plan_sha256": "c" * 64, "registration_required": False, "observed_runner_id": 42}
        return dict(plan)

    def package(staging):
        state["calls"].append("download")
        root = staging / "package"
        (root / "bin").mkdir(parents=True)
        for relative in ("config.cmd", "run.cmd", "bin/Runner.Listener.exe"):
            (root / relative).write_text("official-package-test-double", encoding="utf-8")
        return root

    def version(root):
        state["calls"].append("version")
        return "2.338.2"

    def before_registration(**kwargs):
        state["calls"].append("revalidate")

    def token():
        state["calls"].append("token")
        return "synthetic-registration-token"

    def configure(root, value):
        assert root == home
        assert value == "synthetic-registration-token"
        state["calls"].append("configure")
        (root / ".runner").write_text('{"agentId":42}', encoding="utf-8")
        state["registered"] = True

    monkeypatch.setattr(bootstrap, "orchestrator_dev_plan", current_plan)
    monkeypatch.setattr(bootstrap, "_OrchestratorApplyLock", lambda root: nullcontext())
    monkeypatch.setattr(bootstrap, "_orchestrator_download_package", package)
    monkeypatch.setattr(bootstrap, "_orchestrator_version_probe", version)
    monkeypatch.setattr(bootstrap, "_orchestrator_pre_registration", before_registration)
    monkeypatch.setattr(bootstrap, "_orchestrator_registration_token", token)
    monkeypatch.setattr(bootstrap, "_orchestrator_configure", configure)
    monkeypatch.setattr(bootstrap, "_orchestrator_readback", lambda *args: {
        "registration_required": not state["registered"],
        "observed_runner_id": 42 if state["registered"] else None,
    })

    def forbidden(*args, **kwargs):
        pytest.fail("registration must not start, stop or configure Runtime")

    monkeypatch.setattr(bootstrap.watchdog, "start_runner", forbidden)
    monkeypatch.setattr(bootstrap.watchdog, "stop_runner", forbidden)
    monkeypatch.setattr(bootstrap, "register_runner", forbidden)
    return home, state, plan


def apply():
    return bootstrap.apply_orchestrator_dev_plan(
        source_sha=SHA, correlation_id=CORRELATION,
        expected_plan_sha256=DIGEST, confirm=bootstrap.ORCHESTRATOR_APPLY_CONFIRM,
    )


def test_apply_requires_digest_then_registers_once_and_replays_without_effects(apply_environment):
    home, state, _ = apply_environment
    first = apply()
    assert first["ok"] is True
    assert first["state"] == "RUNNER_REGISTERED_ACTIVATION_PENDING"
    assert first["registered_runner_id"] == 42
    assert first["registration_performed"] is True
    assert first["runner_started"] is False
    assert first["watchdog_changed"] is False
    assert first["physical_pickup_proven"] is False
    assert state["calls"] == ["download", "version", "revalidate", "token", "configure"]
    files = {str(path.relative_to(home)): path.read_bytes() for path in home.rglob("*") if path.is_file()}
    second = apply()
    assert second["ok"] is True
    assert second["state"] == "RUNNER_ALREADY_REGISTERED_ACTIVATION_PENDING"
    assert second["registered_runner_id"] == 42
    assert second["read_only"] is True
    assert second["registration_performed"] is False
    assert second["no_mutation_required"] is True
    assert len(state["calls"]) == 5
    assert {str(path.relative_to(home)): path.read_bytes() for path in home.rglob("*") if path.is_file()} == files


def test_changed_plan_blocks_all_mutations(apply_environment):
    home, state, plan = apply_environment
    plan["plan_sha256"] = "d" * 64
    result = apply()
    assert result["state"] == "orchestrator_plan_changed"
    assert state["calls"] == []
    assert not home.exists()


def test_version_failure_prevents_install_and_registration(apply_environment, monkeypatch):
    home, state, _ = apply_environment

    def reject(root):
        raise bootstrap.BootstrapError("orchestrator_runner_binary_version_mismatch", "safe")

    monkeypatch.setattr(bootstrap, "_orchestrator_version_probe", reject)
    result = apply()
    assert result["ok"] is False
    assert result["state"] == "orchestrator_runner_binary_version_mismatch"
    assert result["package_installed"] is False
    assert result["registration_token_requested"] is False
    assert "token" not in state["calls"]
    assert not home.exists()


def test_pre_registration_drift_never_requests_token(apply_environment, monkeypatch):
    home, state, _ = apply_environment

    def reject(**kwargs):
        raise bootstrap.BootstrapError("orchestrator_registration_state_changed", "safe")

    monkeypatch.setattr(bootstrap, "_orchestrator_pre_registration", reject)
    result = apply()
    assert result["ok"] is False
    assert result["package_installed"] is True
    assert result["registration_token_requested"] is False
    assert result["partial_installation_preserved"] is True
    assert "token" not in state["calls"]
    assert home.is_dir()


def test_uncertain_registration_keeps_observed_id_without_delete_or_retry(
    apply_environment, monkeypatch,
):
    home, state, _ = apply_environment

    def uncertain(root, token):
        state["calls"].append("configure")
        raise RuntimeError("synthetic-registration-token-must-not-be-disclosed")

    monkeypatch.setattr(bootstrap, "_orchestrator_configure", uncertain)
    monkeypatch.setattr(probe, "registry_snapshot", lambda **kwargs: {"id": 77})
    result = apply()
    assert result["ok"] is False
    assert result["registration_performed"] is None
    assert result["registration_command_invoked"] is True
    assert result["observed_runner_id_after_failure"] == 77
    assert result["observed_id_creation_proven"] is False
    assert result["automatic_unregistration_performed"] is False
    assert result["partial_installation_preserved"] is True
    assert "synthetic-registration-token" not in json.dumps(result)
    assert home.is_dir()
    assert state["calls"].count("configure") == 1


def test_apply_never_accepts_invalid_confirmation_or_digest(apply_environment):
    home, state, _ = apply_environment
    for confirmation, digest, expected in [
        ("wrong", DIGEST, "confirmation_invalid"),
        (bootstrap.ORCHESTRATOR_APPLY_CONFIRM, "bad", "orchestrator_plan_digest_invalid"),
    ]:
        result = bootstrap.apply_orchestrator_dev_plan(
            source_sha=SHA, correlation_id=CORRELATION,
            expected_plan_sha256=digest, confirm=confirmation,
        )
        assert result["state"] == expected
    assert state["calls"] == []
    assert not home.exists()


def test_local_auth_mode_never_uses_workflow_token(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "synthetic-workflow-token")
    tokens = []

    def api(path, *, method="GET", token):
        tokens.append(token)
        return {"total_count": 0, "runners": []}

    monkeypatch.setattr(probe.bootstrap, "api_json", api)
    assert probe.registry_snapshot(local_auth_only=True) is None
    assert tokens == [None]
    assert probe.registry_snapshot() is None
    assert tokens == [None, "synthetic-workflow-token"]


@pytest.mark.skipif(os.name != "nt", reason="Windows file-lock API; executed by the Windows CI job")
def test_registration_lock_refuses_concurrent_apply_and_releases(tmp_path):
    home = tmp_path / "EngineeringOrchestratorDEV" / "GitHubRunner"
    with bootstrap._OrchestratorApplyLock(home):
        with pytest.raises(bootstrap.BootstrapError) as error:
            with bootstrap._OrchestratorApplyLock(home):
                pytest.fail("second registration lock was acquired")
        assert error.value.state == "orchestrator_bootstrap_lock_unavailable"
    with bootstrap._OrchestratorApplyLock(home):
        pass



import re

b = bootstrap
hp = policy

EXPECTED_ORCHESTRATOR_PROFILE = {
    'target': 'orchestrator-dev',
    'environment': 'dev',
    'host': 'DESKTOP-PDQK954',
    'repository': 'ericson-j-santos/reqsys-engineering-orchestrator',
    'runner_name': 'DESKTOP-PDQK954-orchestrator-dev',
    'directory': 'EngineeringOrchestratorDEV',
}


def runtime_globals_snapshot():
    return (b.REPOSITORY, b.REPOSITORY_URL, b.RUNNER_NAME,
            b.RUNNER_LABELS, b.REQUIRED_LABELS, b.RUNNER_VERSION,
            b.RUNNER_ASSET_URL, b.RUNNER_ASSET_SHA256)


def test_orchestrator_profile_is_closed_and_immutable():
    before = runtime_globals_snapshot()
    original = hp.authorized_host('DESKTOP-PDQK954')
    profile = hp.orchestrator_dev_runner_profile('DESKTOP-PDQK954')
    assert dict(profile) == EXPECTED_ORCHESTRATOR_PROFILE
    assert dict(hp.ORCHESTRATOR_DEV_RUNNER_PROFILE) == EXPECTED_ORCHESTRATOR_PROFILE
    with pytest.raises(TypeError):
        profile['repository'] = 'somewhere/else'
    assert hp.ORCHESTRATOR_DEV_RUNNER_REQUIRED_LABELS == frozenset({
        'self-hosted', 'Windows', 'X64', 'orchestrator-dev', 'desktop-pdqk954',
    })
    with pytest.raises(AttributeError):
        hp.ORCHESTRATOR_DEV_RUNNER_REQUIRED_LABELS.add('runtime-dev')
    assert hp.authorized_host('DESKTOP-PDQK954') == original
    assert runtime_globals_snapshot() == before


@pytest.mark.parametrize('hostname', [
    'DESKTOP-RP23OGS', 'NOTERI', 'DESKTOP-PDQK954-other', 'unlisted-host',
])
def test_orchestrator_profile_rejects_other_hosts_without_changing_runtime(hostname):
    before = runtime_globals_snapshot()
    originals = {name: hp.authorized_host(name) for name in hp.authorized_hostnames()}
    with pytest.raises(ValueError):
        hp.orchestrator_dev_runner_profile(hostname)
    assert {name: hp.authorized_host(name) for name in hp.authorized_hostnames()} == originals
    assert runtime_globals_snapshot() == before


def test_orchestrator_package_contract_is_fixed_and_immutable():
    package = hp.ORCHESTRATOR_DEV_RUNNER_PACKAGE
    assert set(package) == {'version', 'filename', 'url', 'sha256', 'size'}
    assert package['version'] == '2.338.2'
    assert package['filename'] == 'actions-runner-win-x64-2.338.2.zip'
    assert package['url'] == (
        'https://github.com/actions/runner/releases/download/v2.338.2/'
        'actions-runner-win-x64-2.338.2.zip'
    )
    assert re.fullmatch(r'[0-9a-f]{64}', package['sha256'])
    assert type(package['size']) is int and package['size'] > 0
    with pytest.raises(TypeError):
        package['version'] = 'latest'


def test_orchestrator_environment_drops_inherited_credentials_and_input_overrides(monkeypatch):
    original = {
        'PATH': 'tool-path', 'LOCALAPPDATA': 'profile-root', 'KEEP': 'safe',
        'GH_TOKEN': 'inherited-one', 'github_token': 'inherited-two',
        'Runner_Tracking_Id': 'inherited-three',
        'ACTIONS_RUNNER_INPUT_TOKEN': 'inherited-four',
        'actions_runner_input_url': 'https://wrong.invalid',
        'AcTiOnS_RuNnEr_InPuT_RePlAcE': 'true',
    }
    monkeypatch.setattr(b.os, 'environ', original)
    assert b._orchestrator_clean_env() == {
        'PATH': 'tool-path', 'LOCALAPPDATA': 'profile-root', 'KEEP': 'safe',
        'Runner_Tracking_Id': 'inherited-three',
    }
    assert original['GH_TOKEN'] == 'inherited-one'
    assert original['ACTIONS_RUNNER_INPUT_TOKEN'] == 'inherited-four'


@pytest.mark.parametrize('outcome', ['success', 'nonzero', 'timeout', 'interrupt'])
def test_orchestrator_configure_scopes_token_and_preserves_runtime(
    monkeypatch, tmp_path, capsys, outcome,
):
    root = tmp_path / 'EngineeringOrchestratorDEV'
    listener = root / 'bin' / 'Runner.Listener.exe'
    listener.parent.mkdir(parents=True)
    listener.write_bytes(b'not-executed')
    monkeypatch.setattr(b.os, 'environ', {
        'PATH': 'safe-path', 'GH_TOKEN': 'inherited-gh',
        'GITHUB_TOKEN': 'inherited-actions', 'RUNNER_TRACKING_ID': 'inherited-tracking',
        'ACTIONS_RUNNER_INPUT_REPLACE': 'true',
        'actions_runner_input_token': 'inherited-config-token',
    })
    before = runtime_globals_snapshot()
    calls = []
    token = 'test-ephemeral-token-DO-NOT-PERSIST'

    def configured(argv, **kwargs):
        calls.append((list(argv), kwargs, dict(kwargs['env'])))
        if outcome == 'timeout':
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
        if outcome == 'interrupt':
            raise KeyboardInterrupt
        return SimpleNamespace(returncode=0 if outcome == 'success' else 9)

    monkeypatch.setattr(b.subprocess, 'run', configured)
    if outcome == 'timeout':
        with pytest.raises(subprocess.TimeoutExpired):
            b._orchestrator_configure(root, token)
    elif outcome == 'interrupt':
        with pytest.raises(KeyboardInterrupt):
            b._orchestrator_configure(root, token)
    elif outcome == 'nonzero':
        with pytest.raises(b.BootstrapError) as raised:
            b._orchestrator_configure(root, token)
        assert raised.value.state == 'orchestrator_registration_command_failed'
    else:
        assert b._orchestrator_configure(root, token) is None

    assert len(calls) == 1
    argv, kwargs, during = calls[0]
    assert argv == [
        str(listener), 'configure', '--unattended', '--url',
        'https://github.com/ericson-j-santos/reqsys-engineering-orchestrator',
        '--name', 'DESKTOP-PDQK954-orchestrator-dev',
        '--labels', b.ORCHESTRATOR_LABELS, '--work', '_work',
    ]
    assert token not in str(argv)
    assert not ({'--token', '--replace', '--runasservice', '--startuptype', '/c'} & set(argv))
    assert all(Path(arg).name.casefold() not in {'cmd.exe', 'powershell.exe', 'run.cmd', 'config.cmd', 'schtasks.exe'} for arg in argv)
    assert kwargs['cwd'] == root
    assert kwargs['stdin'] == subprocess.DEVNULL
    assert kwargs['timeout'] == 120
    assert kwargs.get('shell', False) is False
    assert during['ACTIONS_RUNNER_INPUT_TOKEN'] == token
    assert during['RUNNER_TRACKING_ID'] == 'inherited-tracking'
    assert {key.casefold() for key in during if key.casefold().startswith('actions_runner_input_')} == {'actions_runner_input_token'}
    assert not ({key.casefold() for key in during} & {'gh_token', 'github_token'})
    assert 'ACTIONS_RUNNER_INPUT_TOKEN' not in kwargs['env']
    assert token not in str(kwargs['env'])
    assert runtime_globals_snapshot() == before
    captured = capsys.readouterr()
    assert captured.out == captured.err == ''


def test_orchestrator_configure_missing_listener_never_calls_subprocess(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        pytest.fail('missing listener must fail before configuration')
    monkeypatch.setattr(b.subprocess, 'run', forbidden)
    with pytest.raises(b.BootstrapError) as raised:
        b._orchestrator_configure(tmp_path / 'EngineeringOrchestratorDEV', 'not-used')
    assert raised.value.state == 'orchestrator_runner_listener_missing'


def forbid_bootstrap_entrypoints(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('rejected CLI must not invoke any bootstrap/plan/apply entrypoint')
    for name in ('bootstrap', 'orchestrator_dev_plan', 'apply_orchestrator_dev_plan'):
        monkeypatch.setattr(b, name, forbidden)


@pytest.mark.parametrize('extra', [
    ['--plan'], ['--apply'],
    ['--correlation-id', 'ci-cycle-closure-20261027'],
    ['--expected-plan-sha256', 'a' * 64],
])
def test_runtime_cli_rejects_orchestrator_options_before_any_work(monkeypatch, capsys, extra):
    forbid_bootstrap_entrypoints(monkeypatch)
    monkeypatch.setattr(sys, 'argv', [
        'bootstrap_dedicated_runtime_runner.py', '--confirm', b.CONFIRM,
        '--source-sha', 'a' * 40, *extra,
    ])
    assert b.main() == 2
    assert json.loads(capsys.readouterr().out)['state'] == 'runtime_extra_mode_rejected'


@pytest.mark.parametrize('extra,expected_state', [
    ([], 'orchestrator_explicit_mode_required'),
    (['--plan', '--evidence-file', 'forbidden-output.json'], 'orchestrator_stdout_evidence_only'),
])
def test_orchestrator_cli_requires_explicit_mode_and_stdout_only(
    monkeypatch, capsys, extra, expected_state,
):
    forbid_bootstrap_entrypoints(monkeypatch)
    monkeypatch.setattr(sys, 'argv', [
        'bootstrap_dedicated_runtime_runner.py', '--target', 'orchestrator-dev',
        '--confirm', b.ORCHESTRATOR_PLAN_CONFIRM, '--source-sha', 'a' * 40,
        '--correlation-id', 'ci-cycle-closure-20261027', *extra,
    ])
    assert b.main() != 0
    assert json.loads(capsys.readouterr().out)['state'] == expected_state


@pytest.mark.parametrize('extra', [
    ['--plan', '--apply'],
    ['--plan', '--repository', 'someone/other'],
    ['--plan', '--runner-home', 'arbitrary-home'],
])
def test_orchestrator_cli_parser_rejects_ambiguous_or_open_targets(monkeypatch, extra):
    forbid_bootstrap_entrypoints(monkeypatch)
    monkeypatch.setattr(sys, 'argv', [
        'bootstrap_dedicated_runtime_runner.py', '--target', 'orchestrator-dev',
        '--confirm', b.ORCHESTRATOR_PLAN_CONFIRM, '--source-sha', 'a' * 40,
        '--correlation-id', 'ci-cycle-closure-20261027', *extra,
    ])
    with pytest.raises(SystemExit) as raised:
        b.main()
    assert raised.value.code == 2


def test_orchestrator_cli_missing_correlation_blocks_before_work(monkeypatch, capsys):
    forbid_bootstrap_entrypoints(monkeypatch)
    monkeypatch.setattr(sys, 'argv', [
        'bootstrap_dedicated_runtime_runner.py', '--target', 'orchestrator-dev',
        '--confirm', b.ORCHESTRATOR_PLAN_CONFIRM,
        '--source-sha', 'a' * 40, '--plan',
    ])
    assert b.main() != 0
    payload = json.loads(capsys.readouterr().out)
    assert payload.get('ok') is False
    assert isinstance(payload.get('state'), str)


def test_legacy_runtime_cli_still_dispatches_only_legacy_bootstrap(monkeypatch, capsys):
    called = []
    def legacy(**kwargs):
        called.append(kwargs)
        return {'ok': True, 'state': 'legacy-contract-test'}
    def forbidden(*args, **kwargs):
        pytest.fail('legacy Runtime CLI must not call orchestrator branch')
    monkeypatch.setattr(b, 'bootstrap', legacy)
    monkeypatch.setattr(b, 'orchestrator_dev_plan', forbidden)
    monkeypatch.setattr(b, 'apply_orchestrator_dev_plan', forbidden)
    monkeypatch.setattr(sys, 'argv', [
        'bootstrap_dedicated_runtime_runner.py', '--confirm', b.CONFIRM,
        '--source-sha', 'b' * 40,
    ])
    assert b.main() == 0
    assert called == [{'source_sha': 'b' * 40, 'evidence_file': None}]
    assert json.loads(capsys.readouterr().out)['state'] == 'legacy-contract-test'
