'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const {spawnSync} = require('node:child_process');
const {assess, admit, REQUIRED_STEPS} = require('../scripts/reqsys_dev_inventory_admission.cjs');
const {verifyRetry, readHistory, CONTRACT, ADMISSION, PHYSICAL, CONTRACT_STEPS} = require('../scripts/reqsys_dev_inventory_resume.cjs');
const legacy = require('./fixtures/pr71_admission_before_resume.cjs');
const branch = 'fix/reqsys-dev-runtime-readonly-inventory-20261014';
const sha = 'a'.repeat(40), mainSha = 'b'.repeat(40);
const fullName = 'ericson-j-santos/desktop-pc24x7-runtime';
const now = Date.parse('2026-10-14T23:00:00Z');
function fixture() {
  const current = {id: 100, repository: {full_name: fullName}, head_branch: branch,
    head_sha: sha, path: '.github/workflows/reqsys-dev-readonly-inventory.yml', event: 'push',
    run_attempt: 2, run_started_at: '2026-10-14T22:58:30Z', status: 'in_progress', conclusion: null};
  const prior = {...current, run_attempt: 1, status: 'completed', conclusion: 'failure',
    run_started_at: '2026-10-14T22:40:00Z', updated_at: '2026-10-14T22:50:00Z'};
  const priorJobs = [{id: 501, name: ADMISSION, run_id: 100, head_sha: sha, run_attempt: 1,
    status: 'completed', conclusion: 'failure', started_at: '2026-10-14T22:49:00Z', completed_at: '2026-10-14T22:49:01Z'},
    ...PHYSICAL.map((name, index) => ({id: 502 + index, name, run_id: 100, head_sha: sha,
      run_attempt: 1, status: 'completed', conclusion: 'skipped', runner_id: null, runner_name: null, steps: []}))];
  const contract = {id: 601, name: CONTRACT, run_id: 100, head_sha: sha, run_attempt: 2,
    status: 'completed', conclusion: 'success', started_at: '2026-10-14T22:58:31Z',
    completed_at: '2026-10-14T22:59:40Z', steps: CONTRACT_STEPS.map(name => ({name,
      status: 'completed', conclusion: 'success', started_at: '2026-10-14T22:59:00Z',
      completed_at: '2026-10-14T22:59:01Z'}))};
  return {sha, mainSha, currentId: 100, now,
    canary: {id: 90, repository: {full_name: fullName}, head_branch: 'main', head_sha: mainSha,
      path: '.github/workflows/dedicated-runtime-runner-e2e.yml', event: 'workflow_dispatch',
      run_attempt: 1, created_at: '2026-10-14T22:56:00Z', status: 'completed', conclusion: 'success'},
    jobs: [{id: 401, name: 'Pickup on dedicated Desktop runtime runner', run_id: 90, head_sha: mainSha,
      runner_id: 2, runner_name: 'DESKTOP-PDQK954-runtime', status: 'completed', conclusion: 'success',
      started_at: '2026-10-14T22:57:00Z', completed_at: '2026-10-14T22:58:00Z',
      steps: REQUIRED_STEPS.map(name => ({name, status: 'completed', conclusion: 'success'}))}],
    history: [current, {id: 80, head_branch: branch, path: current.path, status: 'completed',
      updated_at: '2026-10-14T22:30:00Z'}],
    retryEvidence: {current: structuredClone(current), jobs: [contract], previous: [{run: prior, jobs: priorJobs}],
      inventory_artifacts_absent: true}};
}
function retry(data) {
  return verifyRetry({current: data.history[0], canary: data.canary, pickup: data.jobs[0],
    evidence: data.retryEvidence, now: data.now});
}
test('regression: the exact previous source rejects a valid changed-precondition retry', () => {
  const oldBytes = fs.readFileSync(path.join(__dirname, 'fixtures/pr71_admission_before_resume.cjs'));
  const hash = crypto.createHash('sha1').update('blob ' + oldBytes.length + '\0').update(oldBytes).digest('hex');
  assert.equal(hash, '01045f0155d1af353ef4c19d1b3559ee2ae61906');
  const input = fixture();
  assert.equal(legacy.assess(input).reason, 'INVENTORY_IDENTITY_OR_REPLAY_BLOCKED');
  assert.equal(assess(input).ready, true);
});
test('positive retry is deterministic and never mutates supplied evidence', () => {
  const data = fixture(), before = structuredClone(data);
  assert.equal(retry(data).ready, true);
  assert.deepEqual(assess(data), assess(structuredClone(data)));
  assert.deepEqual(data, before);
});
const negatives = [
  ['missing attempt evidence', d => {delete d.retryEvidence;}],
  ['incomplete history', d => {d.retryEvidence.previous = [];}],
  ['wrong previous SHA', d => {d.retryEvidence.previous[0].run.head_sha = mainSha;}],
  ['wrong repository', d => {d.retryEvidence.current.repository.full_name = 'other/repo';}],
  ['wrong branch', d => {d.retryEvidence.current.head_branch = 'main';}],
  ['wrong workflow', d => {d.retryEvidence.current.path = '.github/workflows/ci.yml';}],
  ['wrong previous attempt number', d => {d.retryEvidence.previous[0].run.run_attempt = 2;}],
  ['previous run still active', d => {d.retryEvidence.previous[0].run.status = 'in_progress';}],
  ['previous run succeeded', d => {d.retryEvidence.previous[0].run.conclusion = 'success';}],
  ['prior canary reused', d => {d.retryEvidence.previous[0].run.updated_at = '2026-10-14T22:56:00Z';}],
  ['historical canary rerun', d => {d.canary.run_attempt = 2;}],
  ['wrong canary event', d => {d.canary.event = 'push';}],
  ['retry began before canary completed', d => {d.retryEvidence.current.run_started_at = '2026-10-14T22:57:30Z';}],
  ['prior admission not failed', d => {d.retryEvidence.previous[0].jobs[0].conclusion = 'success';}],
  ['prior physical job executed', d => {d.retryEvidence.previous[0].jobs[1].conclusion = 'success';}],
  ['prior physical runner assigned', d => {d.retryEvidence.previous[0].jobs[1].runner_id = 2;}],
  ['prior physical steps present', d => {d.retryEvidence.previous[0].jobs[1].steps = [{name: 'Set up job'}];}],
  ['duplicate physical job', d => {d.retryEvidence.previous[0].jobs.push(d.retryEvidence.previous[0].jobs[1]);}],
  ['cached contract has current attempt but old start', d => {d.retryEvidence.jobs[0].started_at = '2026-10-14T22:40:00Z';}],
  ['contract old attempt', d => {d.retryEvidence.jobs[0].run_attempt = 1;}],
  ['contract not executed', d => {d.retryEvidence.jobs[0].conclusion = 'skipped';}],
  ['contract mandatory step skipped', d => {d.retryEvidence.jobs[0].steps[0].conclusion = 'skipped';}],
  ['contract step inherited from old attempt', d => {d.retryEvidence.jobs[0].steps[0].started_at = '2026-10-14T22:40:00Z';}],
  ['contract step timestamp invalid', d => {d.retryEvidence.jobs[0].steps[0].completed_at = 'invalid';}],
  ['duplicate contract', d => {d.retryEvidence.jobs.push(d.retryEvidence.jobs[0]);}],
  ['old inventory artifact exists', d => {d.retryEvidence.inventory_artifacts_absent = false;}],
  ['unknown artifact state', d => {delete d.retryEvidence.inventory_artifacts_absent;}],
  ['expired pickup', d => {d.now += 900001;}],
  ['different run concurrently active', d => {d.history[1].status = 'in_progress';}],
];
for (const [name, mutate] of negatives) test('retry fails closed: ' + name, () => {
  const data = fixture(); mutate(data); assert.equal(assess(data).ready, false);
});
function api(data) {
  const calls = [];
  const copy = value => ({data: structuredClone(value)});
  const actions = {
    listWorkflowRuns: async args => {
      calls.push(['listWorkflowRuns', args]);
      const runs = args.workflow_id.startsWith('dedicated-') ? [data.canary] : data.history;
      return copy({workflow_runs: runs.slice(((args.page || 1) - 1) * 100, (args.page || 1) * 100), total_count: runs.length});
    },
    listJobsForWorkflowRun: async args => {calls.push(['listJobsForWorkflowRun', args]); return copy({jobs: data.jobs, total_count: data.jobs.length});},
    getWorkflowRunAttempt: async args => {
      calls.push(['getWorkflowRunAttempt', args]);
      return copy(args.attempt_number === 2 ? data.retryEvidence.current : data.retryEvidence.previous[args.attempt_number - 1].run);
    },
    listJobsForWorkflowRunAttempt: async args => {
      calls.push(['listJobsForWorkflowRunAttempt', args]);
      const jobs = args.attempt_number === 2 ? data.retryEvidence.jobs : data.retryEvidence.previous[args.attempt_number - 1].jobs;
      return copy({jobs, total_count: jobs.length});
    },
    listWorkflowRunArtifacts: async args => {calls.push(['listWorkflowRunArtifacts', args]); return copy({artifacts: [], total_count: 0});},
    getWorkflowRun: async args => {calls.push(['getWorkflowRun', args]); return copy(data.retryEvidence.current);},
  };
  return {calls, github: {rest: {actions, repos: {getBranch: async args => {
    calls.push(['getBranch', args]); return copy({commit: {sha: args.branch === 'main' ? mainSha : sha}});
  }}}}};
}
function state() {
  const outputs = {}, failures = [];
  return {outputs, failures, context: {repo: {owner: 'ericson-j-santos', repo: 'desktop-pc24x7-runtime'},
    ref: 'refs/heads/' + branch, sha, runId: 100}, now: () => now,
    core: {setOutput: (k, v) => {outputs[k] = v;}, setFailed: x => failures.push(x), info: () => {}}};
}
test('adapter verifies attempts via read APIs and binds positive output to attempt 2', async () => {
  const data = fixture(), {github, calls} = api(data), s = state();
  await admit({...s, github});
  assert.deepEqual(s.failures, []);
  assert.equal(s.outputs.physical_ready, 'true'); assert.equal(s.outputs.admitted_attempt, '2');
  assert.deepEqual(calls.filter(c => c[0] === 'getWorkflowRunAttempt').map(c => c[1].attempt_number), [2, 1]);
  assert.ok(calls.every(c => /^(get|list)/.test(c[0])));
});
test('adapter blocks API errors without disclosing raw error or keeping positive output', async () => {
  const {github} = api(fixture()), s = state(); s.outputs.physical_ready = 'true';
  github.rest.actions.getWorkflowRunAttempt = async () => {throw Error('PRIVATE_TEST_MARKER');};
  await admit({...s, github});
  assert.equal(s.outputs.physical_ready, 'false'); assert.equal(s.outputs.admitted_attempt, '');
  assert.deepEqual(s.failures, ['ADMISSION_READBACK_UNAVAILABLE']);
  assert.ok(!JSON.stringify(s.outputs).includes('PRIVATE_TEST_MARKER'));
});
test('adapter blocks copied contract evidence with current run_attempt and old timestamp', async () => {
  const data = fixture(); data.retryEvidence.jobs[0].started_at = '2026-10-14T22:40:00Z';
  const s = state(); await admit({...s, github: api(data).github});
  assert.equal(s.outputs.physical_ready, 'false');
  assert.deepEqual(s.failures, ['FRESH_CONTRACT_FOR_THIS_ATTEMPT_REQUIRED']);
});
test('adapter rejects attempt changes during readback', async () => {
  const data = fixture(), {github} = api(data), s = state();
  github.rest.actions.getWorkflowRun = async () => ({data: {...data.retryEvidence.current, run_attempt: 3}});
  await admit({...s, github}); assert.deepEqual(s.failures, ['ADMISSION_SOURCE_OR_ATTEMPT_CHANGED']);
});
test('adapter rechecks freshness after transport', async () => {
  const s = state(); let observations = 0;
  await admit({...s, github: api(fixture()).github, now: () => now + (observations++ ? 900001 : 0)});
  assert.equal(s.outputs.physical_ready, 'false'); assert.equal(s.outputs.admitted_attempt, '');
});
test('history pagination reads beyond the previous twenty-run window', async () => {
  const data = fixture(); data.history = Array.from({length: 101}, (_, i) => ({id: i + 1}));
  const {github, calls} = api(data);
  assert.equal((await readHistory(github, {})).length, 101);
  assert.deepEqual(calls.map(c => c[1].page), [1, 2]);
});
for (const [name, response] of [
  ['missing total', {workflow_runs: [{id: 1}]}],
  ['incomplete page', {workflow_runs: [{id: 1}], total_count: 2}],
  ['duplicate ID', {workflow_runs: [{id: 1}, {id: 1}], total_count: 2}],
  ['over limit', {workflow_runs: [], total_count: 1001}],
]) test('history fails closed: ' + name, async () => {
  const github = {rest: {actions: {listWorkflowRuns: async () => ({data: response})}}};
  await assert.rejects(readHistory(github, {}));
});
function workflow() {return fs.readFileSync(path.join(__dirname, '../.github/workflows/reqsys-dev-readonly-inventory.yml'), 'utf8').replace(/\r\n?/g, '\n');}
function block(name) {
  return workflow().split('      - name: ' + name + '\n')[1]
    .split('      - name: ')[0].split(/\n  [a-z_]+:\n/)[0];
}
function script(name, kind) {
  return block(name).split(kind === 'js' ? '          script: |\n' : '        run: |\n')[1]
    .trimEnd().split('\n').map(line => line.slice(kind === 'js' ? 12 : 10)).join('\n');
}
test('workflow includes retry paths, attempt-specific artifact and pinned admission output', () => {
  const text = workflow();
  assert.ok(text.includes('      - scripts/reqsys_dev_inventory_resume.cjs\n'));
  assert.ok(text.includes('      - tests/test_reqsys_dev_inventory_resume.cjs\n'));
  assert.ok(text.includes('admitted_attempt: ${{ steps.admit.outputs.admitted_attempt }}'));
  assert.ok(text.includes('name: reqsys-dev-readonly-inventory-${{ github.run_id }}-${{ github.run_attempt }}'));
  assert.ok(text.includes('node --check scripts/reqsys_dev_inventory_resume.cjs'));
});
test('PowerShell parser validates the exact physical workflow scripts without executing them', () => {
  const code = ['Bootstrap isolated session with exact SHA and runner preflight',
    'Read-only Docker, Compose, image and database metadata through Gateway',
    'Independently read back sanitized inventory receipt'].map(name => script(name, 'ps')).join('\n');
  const command = '$t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$t,[ref]$e); if($e.Count){$e | ForEach-Object { Write-Output $_.Message }; exit 1}';
  const result = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', command], {input: code, encoding: 'utf8', timeout: 15000});
  assert.equal(result.status, 0, result.error?.message || result.stdout || result.stderr);
});
test('physical bootstrap guard executes positive and negative controls before any host command', () => {
  const guard = script('Bootstrap isolated session with exact SHA and runner preflight', 'ps')
    .split("if ($env:COMPUTERNAME")[0];
  assert.ok(guard.includes('FRESH_ADMISSION_FOR_THIS_ATTEMPT_REQUIRED'));
  for (const [admitted, attempt, expected] of [['2', '2', 0], ['1', '2', 1], ['', '2', 1]]) {
    const result = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', guard], {
      encoding: 'utf8', timeout: 15000, env: {...process.env, ADMITTED_ATTEMPT: admitted, GITHUB_RUN_ATTEMPT: attempt},
    });
    assert.equal(result.status, expected, result.error?.message || result.stderr);
  }
});
test('watchdog exact attempt guard suppresses stale-output replay', async () => {
  const source = script('Stop stalled acquisition without repeating physical dispatch', 'js');
  for (const [admitted, attempt, expectedCalls] of [['2', '2', 1], ['1', '2', 0], ['', '2', 0]]) {
    let calls = 0; const failures = [];
    const sandbox = {process: {env: {ADMITTED_ATTEMPT: admitted, GITHUB_RUN_ATTEMPT: attempt}},
      core: {setFailed: x => failures.push(x)}, github: {}, context: {},
      require: () => ({monitor: async () => {calls++;}})};
    await vm.runInNewContext('(async () => {' + source + '})()', sandbox, {timeout: 1000});
    assert.equal(calls, expectedCalls);
    assert.equal(failures.length, expectedCalls ? 0 : 1);
  }
});
