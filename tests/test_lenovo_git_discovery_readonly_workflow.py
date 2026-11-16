from __future__ import annotations
import json
import os
import subprocess
from pathlib import Path
import pytest
import yaml

SOURCE=(Path(__file__).resolve().parents[1]/".github/workflows/lenovo-git-discovery-readonly.yml").read_text(encoding="utf-8")
SPEC=yaml.load(SOURCE,Loader=yaml.BaseLoader)
JOB=SPEC["jobs"]["discover"]
SCRIPT=JOB["steps"][0]["with"]["script"]
HARNESS=r"""
const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
const sha='a'.repeat(40);
const github={rest:{
  repos:{getBranch:async()=>({data:{commit:{sha}}})},
  actions:{
    listWorkflowRuns:async()=>({data:{workflow_runs:[{
      head_sha:sha,head_branch:'main',event:'push',conclusion:'success',
      repository:{full_name:'ericson-j-santos/desktop-pc24x7-runtime'},id:1
    }]}}),
    listJobsForWorkflowRun:async()=>({data:{total_count:2,jobs:[
      ['Python compile and tests','windows-latest'],
      ['Portable Linux compile and tests','ubuntu-latest']
    ].map(([name,label])=>({name,labels:[label],conclusion:'success',
      steps:[{name:'Unit and negative-control tests',conclusion:'success'}]}))}})
  }
}};
const context={eventName:'workflow_dispatch',actor:'ericson-j-santos',
  repo:{owner:'ericson-j-santos',repo:'desktop-pc24x7-runtime'},
  ref:'refs/heads/main',sha:process.env.TEST_SHA||sha};
(async()=>{await new AsyncFunction('github','context','core','require',
  process.env.TEST_SCRIPT)(github,context,{info:x=>console.log(x)},require);
})().catch(e=>{console.error(e.message);process.exitCode=1});
"""

def probe(tmp_path,present=False,host="DESKTOP-RP23OGS",
          runner="DESKTOP-RP23OGS-runtime",sha=""):
    if present:
        f=tmp_path/"Git"/"cmd"/"git.exe"
        f.parent.mkdir(parents=True,exist_ok=True)
        f.write_bytes(b"not-an-executable")
    env=dict(os.environ)
    env.update({"TEST_SCRIPT":SCRIPT,"TEST_SHA":sha,
        "EXPECTED_SOURCE_SHA":"a"*40,
        "CONFIRMATION":"READ_ONLY_LENOVO_GIT_DISCOVERY",
        "GITHUB_RUN_ATTEMPT":"1",
        "COMPUTERNAME":host,"RUNNER_NAME":runner,
        "ProgramFiles":str(tmp_path),"ProgramW6432":str(tmp_path),
        "ProgramFiles(x86)":str(tmp_path),
        "LOCALAPPDATA":str(tmp_path),"ProgramData":str(tmp_path)})
    return subprocess.run(["node","-e",HARNESS],env=env,capture_output=True,
        text=True,check=False,timeout=15)

def test_guards_and_no_uncontrolled_local_shell():
    assert set(SPEC["on"])=={"workflow_dispatch"}
    assert SPEC["permissions"]=={"contents":"read","actions":"read"}
    assert JOB["runs-on"]==["self-hosted","Windows","X64","pc24x7",
        "desktop-runtime","runtime-dev","desktop-rp23ogs"]
    assert JOB["environment"]=="DEV"
    assert "vars.REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA == github.sha" in JOB["if"]
    assert len(JOB["steps"])==1
    assert JOB["steps"][0]["uses"]=="actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea"
    assert all("shell" not in step and "run" not in step for step in JOB["steps"])
    for forbidden in ("shell: python","actions/checkout@","child_process",
                      "execFile(","execSync(","spawn(","writeFile(","rmSync("):
        assert forbidden not in SOURCE
    assert SCRIPT.index("LENOVO_BOOTSTRAP_HOST_REJECTED")<SCRIPT.index("require('node:fs')")
    for flag in ("git_verified:false","session_launch_ok:false","state_validated:false",
                 "execution_authorized:false","mutation_performed:false"):
        assert flag in SCRIPT

@pytest.mark.parametrize("present,expected",[(False,"missing"),(True,"file_present_unverified")])
def test_real_node_presence_and_idempotent_replay(tmp_path,present,expected):
    result=probe(tmp_path,present=present)
    assert result.returncode==0,result.stderr
    marker="LENOVO_BOOTSTRAP_DEPENDENCY_CHECK "
    assert result.stdout.count(marker)==1
    receipt=json.loads(result.stdout.split(marker,1)[1])
    assert {r["candidate"]:r["state"] for r in receipt["candidates"]}["system"]==expected
    assert receipt["git_verified"] is False
    assert receipt["session_launch_ok"] is False
    assert receipt["state_validated"] is False
    assert receipt["execution_authorized"] is False
    assert receipt["mutation_performed"] is False
    assert probe(tmp_path,present=present).stdout==result.stdout

@pytest.mark.parametrize("host,runner,sha,error",[
    ("WRONG","DESKTOP-RP23OGS-runtime","","LENOVO_BOOTSTRAP_HOST_REJECTED"),
    ("DESKTOP-RP23OGS","WRONG","","LENOVO_BOOTSTRAP_HOST_REJECTED"),
    ("DESKTOP-RP23OGS","DESKTOP-RP23OGS-runtime","b"*40,
     "LENOVO_GIT_DISCOVERY_ADMISSION_REJECTED")
])
def test_wrong_host_runner_or_sha_rejected(tmp_path,host,runner,sha,error):
    result=probe(tmp_path,host=host,runner=runner,sha=sha)
    assert result.returncode!=0
    assert error in result.stderr
    assert "LENOVO_BOOTSTRAP_DEPENDENCY_CHECK" not in result.stdout
