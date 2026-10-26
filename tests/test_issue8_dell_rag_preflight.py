"""Issue8 Dell physical RAG preflight: fail-closed, no side effects.

Live GitHub admission/Ollama are deliberately NOT faked into acceptance.
These are contract fixtures; the physical workflow must prove actual calls.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "issue8_dell_rag_preflight.py"
WORKFLOW = ROOT / ".github/workflows/issue8-dell-native-rag-readonly.yml"


def module():
    s=importlib.util.spec_from_file_location("issue8_dell_rag_preflight",SCRIPT)
    assert s is not None and s.loader is not None
    x=importlib.util.module_from_spec(s)
    sys.modules[s.name]=x
    s.loader.exec_module(x)
    return x


def valid_env(m, workspace):
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": m.HOST_REPOSITORY,
        "RUNNER_NAME": "DESKTOP-PDQK954-runtime",
        "COMPUTERNAME": "DESKTOP-PDQK954",
        "NATIVE_OLLAMA_DEV": "1",
        "NATIVE_MODEL_DIGEST_PREFIX": m.MODEL_PIN,
        "SESSION_LAUNCH_RESULT": "SESSION_LAUNCH_OK",
        "SESSION_STATE_VALIDATED": "true",
        "SESSION_GATEWAY_BOUND": "true",
        "SESSION_ID": "issue8-dell-test-1",
        "SESSION_SNAPSHOT_SHA256": "a"*64,
        "CORRELATION_ID": "issue8-dell-12345-1",
        "EXPECTED_RUNTIME_SHA": "b"*40,
        "WORKER_POOL_SHA": m.WORKER_SHA,
        "RULES_SHA": m.RULES_SHA,
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_WORKSPACE": str(workspace),
        "SESSION_TARGET_PATH": str(workspace / "session"),
    }


def test_positive_host_identity_does_not_authorize_execution(tmp_path):
    m=module()
    a=m.validate_environment(valid_env(m,tmp_path))
    assert a["runtime_sha"]=="b"*40
    assert a["run_id"]=="12345"
    assert m.MODEL_PIN=="dae161e27b0e"
    assert m.WORKER_SHA=="74035488dac6938bfc14957621e86168003cd0c6"
    assert m.OWNER_COMMENT_ID==6404265064


@pytest.mark.parametrize("field,value",[
    ("GITHUB_ACTIONS","false"),
    ("GITHUB_REPOSITORY","untrusted/repo"),
    ("RUNNER_NAME","Dell-legacy"),
    ("NATIVE_OLLAMA_DEV","0"),
    ("NATIVE_MODEL_DIGEST_PREFIX",""),
    ("SESSION_LAUNCH_RESULT","DIAGNOSTIC_OK"),
    ("SESSION_STATE_VALIDATED","false"),
    ("SESSION_GATEWAY_BOUND","false"),
    ("SESSION_ID","bad session"),
    ("SESSION_SNAPSHOT_SHA256","x"*64),
    ("CORRELATION_ID","bad; injection"),
    ("EXPECTED_RUNTIME_SHA","abc"),
    ("WORKER_POOL_SHA","c"*40),
    ("RULES_SHA","c"*40),
    ("GITHUB_RUN_ID","unsafe"),
    ("GITHUB_RUN_ATTEMPT","0"),
    ("GITHUB_WORKSPACE",""),
])
def test_host_or_owner_context_fail_before_inference(tmp_path,field,value,monkeypatch):
    m=module()
    env=valid_env(m,tmp_path)
    env[field]=value
    called=[]
    monkeypatch.setattr(m,"verify_pinned_checkout",lambda *_: called.append(True))
    with pytest.raises(m.PreflightBlocked):
        m.run(env)
    assert not called


def test_read_only_git_whitelist(monkeypatch,tmp_path):
    m=module()
    seen=[]
    def execute(cmd,**kw):
        seen.append(cmd)
        assert cmd[:1]==["git"] and cmd[1:] in (
            ["rev-parse","HEAD"],
            ["status","--porcelain","--untracked-files=no"],
        )
        assert kw["env"]["GIT_TERMINAL_PROMPT"]=="0"
        assert kw["env"]["GIT_OPTIONAL_LOCKS"]=="0"
        assert kw["check"] is False
        return subprocess.CompletedProcess(cmd,0,"a"*40+"\n","")
    monkeypatch.setattr(m.subprocess,"run",execute)
    assert m.read_git(tmp_path,"rev-parse","HEAD")=="a"*40
    with pytest.raises(m.PreflightBlocked,match="issue8_git_action_not_allowlisted"):
        m.read_git(tmp_path,"push","--force")
    assert seen==[["git","rev-parse","HEAD"]]


def test_git_error_is_sanitized(monkeypatch,tmp_path):
    m=module()
    monkeypatch.setattr(m.subprocess,"run",lambda *a,**k:
                        subprocess.CompletedProcess(a,128,"","TOKEN=SENSITIVE"))
    with pytest.raises(m.PreflightBlocked,match="^issue8_git_sha_invalid$") as x:
        m.read_git(tmp_path,"rev-parse","HEAD")
    assert "SENSITIVE" not in str(x.value)


def test_source_blob_revalidated_before_any_model(monkeypatch,tmp_path):
    m=module()
    env=valid_env(m,tmp_path)
    workspace=tmp_path
    (workspace/"session"/"scripts").mkdir(parents=True)
    (workspace/"session"/"scripts"/"issue8_dell_rag_preflight.py").write_text("pass\n")
    (workspace/"_worker_pool"/"app").mkdir(parents=True)
    (workspace/"_rules").mkdir()
    content=b"from source at pinned SHA\n"
    (workspace/"_worker_pool"/m.SOURCE_PATH).write_bytes(content)
    digest=hashlib.sha1(
        b"blob "+str(len(content)).encode()+b"\0"+content,
    ).hexdigest()
    monkeypatch.setattr(m,"SOURCE_BLOB_SHA",digest)
    monkeypatch.setattr(m,"canonical_git_source",lambda _root: content)
    def get(root,*args):
        if args==("status","--porcelain","--untracked-files=no"):
            return ""
        return (env["EXPECTED_RUNTIME_SHA"] if root.name=="session"
                else m.WORKER_SHA if root.name=="_worker_pool" else m.RULES_SHA)
    monkeypatch.setattr(m,"read_git",get)
    identity=m.validate_environment(env)
    worker,raw=m.verify_pinned_checkout(env,identity)
    assert worker.name=="_worker_pool" and raw==content
    (workspace/"_worker_pool"/m.SOURCE_PATH).write_bytes(content+b"tampered")
    with pytest.raises(m.PreflightBlocked,match="issue8_checkout_bytes_drift"):
        m.verify_pinned_checkout(env,identity)


def test_source_get_allows_only_exact_static_paths_and_sha():
    m=module()
    class Reader:
        def get_text_file(self,repo,path,sha):
            payload=b"# independently cited evidence\n"
            sha1=hashlib.sha1(
                b"blob "+str(len(payload)).encode()+b"\0"+payload,
            ).hexdigest()
            return {
                "type":"file","path":path,"encoding":"base64",
                "size":len(payload),"content":base64.b64encode(payload).decode(),
                "sha":sha1,
            }
    r=Reader()
    assert m.read_original_bytes(r,"README.md",m.WORKER_SHA).startswith(b"#")
    for path in ("app/portfolio_bridge.py","docs/private.md","../secrets.md"):
        with pytest.raises(m.PreflightBlocked,match="issue8_independent_path_invalid"):
            m.read_original_bytes(r,path,m.WORKER_SHA)
    with pytest.raises(m.PreflightBlocked,match="issue8_independent_path_invalid"):
        m.read_original_bytes(r,"README.md","0"*40)


def test_nonzero_on_unknown_exception_avoids_secret_leak(monkeypatch,capsys):
    m=module()
    monkeypatch.setattr(m,"run",lambda *_: (_ for _ in ()).throw(
        RuntimeError("secret bearer token")))
    assert m.main()==2
    msg=json.loads(capsys.readouterr().out)
    assert msg["result"]=="ISSUE8_NATIVE_RAG_PREFLIGHT_BLOCKED"
    assert msg["reason_code"]=="issue8_native_dependency_unavailable"
    assert "bearer" not in json.dumps(msg)


def test_workflow_has_gated_one_shot_routing_and_no_write_permissions():
    t=WORKFLOW.read_text(encoding="utf-8")
    assert "types: [edited]" in t
    assert "github.actor == 'ericson-j-santos'" in t
    assert "github.event.changes.body.from != null" in t
    assert "OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_ONCE" in t
    assert "ISSUE8_SANITIZED_FAILURE=" in t
    assert "^(?:issue8_|rag_|main_|owner_|native_|github_|context_)[a-z0-9_]{2,95}$" in t
    assert "ISSUE8_NATIVE_RAG_PREFLIGHT_BLOCKED" in t
    assert "gatewayStatus -ne 0" in t
    assert "2>&1" in t
    assert "!contains(github.event.changes.body.from, 'OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_ONCE')" in t
    assert "throw 'ISSUE8_NATIVE_RAG_GATEWAY_BLOCKED'" in t
    assert "runner_name" in t
    assert "DESKTOP-PDQK954-runtime" in t
    assert "6404265064" in t
    assert m_sha_in_text(t)
    assert "--require-runner-version-preflight" in t
    assert "SESSION_LAUNCH_OK" in t
    assert "command_gateway.py" in t
    assert "'--risk','1'" in t and "'--risk','2'" in t
    assert "ISSUE8_NATIVE_RAG_PREFLIGHT_VERIFIED" in t
    assert "300000" in t and "cancelWorkflowRun" in t
    assert "sudo " not in t.lower()
    assert "docker " not in t.lower()
    assert "ollama pull" not in t.lower()
    assert "force-push" not in t.lower()
    assert "contents: write" not in t


def m_sha_in_text(t):
    return ("74035488dac6938bfc14957621e86168003cd0c6" in t
            and "92e8b5c87684212964b24ff3597f9f9f8aea49a6" in t)



def test_dell_workflow_yaml_parses_and_corruption_fails(tmp_path):
    """Portable syntax gate: required Windows and Linux checks must both execute."""
    import yaml
    raw = WORKFLOW.read_text(encoding="utf-8")
    parsed = yaml.load(raw, Loader=yaml.BaseLoader)
    assert set(parsed) >= {"name", "on", "jobs", "permissions"}
    assert parsed["on"]["pull_request"]["types"] == ["edited"]
    assert {"contract", "admission", "physical", "watchdog", "independent_readback"} <= set(parsed["jobs"])
    assert "DESKTOP-PDQK954-runtime" in raw
    assert "runner_id)===2" in raw and "runner_id!==2" in raw
    assert "OWNER_ISSUE8_NATIVE_RAG_DELL_20261026_ONCE" in raw
    assert "Python compile and tests" in raw and "Portable Linux compile and tests" in raw
    assert "ISSUE8_NATIVE_RAG_PREFLIGHT_VERIFIED" in raw
    assert "contents: write" not in raw
    assert "ollama pull" not in raw.lower()
    with pytest.raises(yaml.YAMLError):
        yaml.load(raw + "\n) {\n", Loader=yaml.BaseLoader)


def test_wrong_computer_blocks_before_checkout(tmp_path, monkeypatch):
    m=module()
    env=valid_env(m,tmp_path)
    env["COMPUTERNAME"]="OTHER-HOST"
    calls=[]
    monkeypatch.setattr(m, "verify_pinned_checkout", lambda *_: calls.append(True))
    with pytest.raises(m.PreflightBlocked, match="issue8_wrong_physical_computer"):
        m.run(env)
    assert calls==[]
