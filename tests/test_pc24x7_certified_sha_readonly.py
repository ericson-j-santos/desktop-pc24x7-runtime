"""Contrato do monitor: nunca escreve, diferencia ausência, divergência e SHA obsoleto.

Node é padrão dos runners Windows/Linux atuais; o teste executa o JS real do YAML
com a API GitHub substituída por GET local simulado. Não é E2E da variável real.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/pc24x7-certified-sha-readonly.yml'
SHA = 'b19db847b63d8f0fcd5fd160bdeee54d3f57b913'
OTHER = 'a' * 40
JS_HARNESS = r'''
const fs = require('fs');
const script = fs.readFileSync(0, 'utf8');
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
let failure = null, calls = [], summaryWritten = false;
const summary = {
  addHeading: function() { return this; },
  addTable: function() { return this; },
  write: async function() { summaryWritten = true; }
};
const core = {summary, info: () => {}, setFailed: x => { failure = x; }};
const context = {
  repo: {owner:'ericson-j-santos', repo:'desktop-pc24x7-runtime'},
  ref: 'refs/heads/main',
  eventName: process.env.EVENT_NAME || 'schedule',
  actor: process.env.ACTOR || 'ericson-j-santos',
  runId: 123
};
const github = {rest:{repos:{getBranch: async ({owner,repo,branch}) => {
  calls.push('GET /repos/' + owner + '/' + repo + '/branches/' + branch);
  return {data:{commit:{sha:process.env.CURRENT_SHA}}};
}}}};
(async () => {
 try {await new AsyncFunction('github','context','core',script)(github,context,core)}
 catch (e) {failure = 'THREW:' + e.message}
 process.stdout.write(JSON.stringify({failure, calls, summaryWritten}));
})().catch(e => {process.stderr.write(e.message);process.exitCode = 1});
'''


def workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))


def test_readonly_scope_triggers_and_permission():
    item = workflow()
    triggers = item.get('on', item.get(True, {}))
    assert set(triggers) == {'push', 'schedule', 'workflow_dispatch'}
    assert triggers['push']['branches'] == ['main']
    assert item['permissions'] == {'contents': 'read'}
    job = item['jobs']['verify']
    assert job['runs-on'] == 'ubuntu-24.04'
    assert 'github.repository ==' in job['if']
    assert 'github.ref ==' in job['if']
    assert job['env']['CERTIFIED_SHA'] == '${{ vars.REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA }}'
    assert job['env']['EXPECTED_SOURCE_SHA'] == '${{ github.sha }}'
    assert len(job['steps']) == 1
    assert job['steps'][0]['uses'].startswith('actions/github-script@')
    source = job['steps'][0]['with']['script']
    assert 'github.rest.repos.getBranch' in source
    assert 'github.rest.actions.' not in source
    assert 'github.rest.actions.' not in source
    assert all(x not in source for x in ['.create', '.update', '.delete', '.dispatch', 'exec(', 'eval('])


@pytest.mark.parametrize('certified,current,event,event_name,actor,expected', [
    (SHA,SHA,SHA,'schedule','ericson-j-santos',None),
    ('',SHA,SHA,'schedule','ericson-j-santos','VARIABLE_MISSING'),
    (OTHER,SHA,SHA,'schedule','ericson-j-santos','VARIABLE_MISMATCH'),
    ('invalid',SHA,SHA,'schedule','ericson-j-santos','VARIABLE_INVALID'),
    (SHA,OTHER,SHA,'schedule','ericson-j-santos','STALE_RUN'),
    (SHA,'bad',SHA,'schedule','ericson-j-santos','SHA_INVALID'),
    (SHA,SHA,SHA,'workflow_dispatch','not-owner','OWNER_REQUIRED'),
])
def test_real_js_fail_closed(certified, current, event, event_name, actor, expected):
    if not shutil.which('node'):
        pytest.fail('node_required_for_readonly_guard_test')
    item = workflow()
    source = item['jobs']['verify']['steps'][0]['with']['script']
    environment = {**os.environ, 'CURRENT_SHA':current, 'EXPECTED_SOURCE_SHA':event,
                   'CERTIFIED_SHA':certified, 'EVENT_NAME':event_name, 'ACTOR':actor}
    result = subprocess.run(['node','-e',JS_HARNESS],input=source,text=True,
                            capture_output=True,env=environment,timeout=10,check=True)
    outcome = json.loads(result.stdout)
    assert outcome['summaryWritten'] is True
    assert outcome['failure'] == (f'CERTIFIED_SHA_READONLY_{expected}' if expected else None)
    assert outcome['calls'] == (['GET /repos/ericson-j-santos/desktop-pc24x7-runtime/branches/main']
                                if expected != 'OWNER_REQUIRED' else [])
