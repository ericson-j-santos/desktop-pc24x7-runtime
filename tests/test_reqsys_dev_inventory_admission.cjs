'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {assess, admit, REQUIRED_STEPS} = require('../scripts/reqsys_dev_inventory_admission.cjs');
const sha = 'a'.repeat(40), mainSha = 'b'.repeat(40);
const now = Date.parse('2026-10-14T23:00:00Z');
const branch = 'fix/reqsys-dev-runtime-readonly-inventory-20261014';
function fixture() {
  return {sha, mainSha, now, currentId: 100,
    canary: {id: 90, repository: {full_name: 'ericson-j-santos/desktop-pc24x7-runtime'},
      path: '.github/workflows/dedicated-runtime-runner-e2e.yml', head_branch: 'main',
      head_sha: mainSha, status: 'completed', conclusion: 'success'},
    jobs: [{name: 'Pickup on dedicated Desktop runtime runner', run_id: 90, head_sha: mainSha,
      runner_id: 123, runner_name: 'DESKTOP-PDQK954-runtime', status: 'completed', conclusion: 'success',
      started_at: '2026-10-14T22:57:00Z', completed_at: '2026-10-14T22:58:00Z',
      steps: REQUIRED_STEPS.map(name => ({name, status: 'completed', conclusion: 'success'}))}],
    history: [{id: 100, head_sha: sha, head_branch: branch, run_attempt: 1},
      {id: 80, path: '.github/workflows/reqsys-dev-readonly-inventory.yml', head_branch: branch,
        status: 'completed', updated_at: '2026-10-14T22:30:00Z'}]};
}
test('positive: exact fresh dedicated pickup admits one read-only inventory', () => {
  assert.deepEqual(assess(fixture()), {ready: true, reason: 'FRESH_DEDICATED_PICKUP_VERIFIED', canary_run_id: 90});
});
test('negative: old, future or malformed evidence never admits', () => {
  for (const stamp of ['2026-10-14T22:00:00Z', '2026-10-14T23:01:00Z', 'invalid']) {
    const data = fixture(); data.jobs[0].completed_at = stamp;
    assert.equal(assess(data).ready, false);
  }
});
test('negative: wrong repository, branch, SHA, host or missing pickup fails closed', () => {
  for (const mutate of [
    d => {d.canary.repository.full_name = 'untrusted/repo';},
    d => {d.canary.head_branch = 'untrusted';}, d => {d.canary.head_sha = sha;},
    d => {d.canary.conclusion = 'failure';}, d => {d.jobs[0].runner_name = 'other';},
    d => {d.jobs[0].runner_id = 0;}, d => {d.jobs[0].head_sha = sha;},
    d => {d.jobs[0].run_id = 91;}, d => {d.jobs[0].steps = [];},
    d => {d.jobs[0].steps[0].conclusion = 'skipped';}, d => {d.jobs.push(d.jobs[0]);},
  ]) { const data = fixture(); mutate(data); assert.equal(assess(data).ready, false); }
});
test('regression: push after a failed inventory cannot reuse old runner evidence', () => {
  const data = fixture(); data.history[1].updated_at = '2026-10-14T22:59:00Z';
  assert.equal(assess(data).reason, 'NEW_RUNNER_PRECONDITION_REQUIRED');
  data.history[1].updated_at = '2026-10-14T22:30:00Z'; data.history[1].status = 'in_progress';
  assert.equal(assess(data).reason, 'NEW_RUNNER_PRECONDITION_REQUIRED');
});
test('replay and missing history cannot manufacture a new precondition', () => {
  const data = fixture(); data.history[0].run_attempt = 2;
  assert.equal(assess(data).reason, 'INVENTORY_IDENTITY_OR_REPLAY_BLOCKED');
  data.history = []; assert.equal(assess(data).ready, false);
  assert.deepEqual(assess(fixture()), assess(fixture()));
});
function api(data) {
  return {rest: {repos: {getBranch: async () => ({data: {commit: {sha: data.mainSha}}})}, actions: {
    listWorkflowRuns: async args => ({data: {workflow_runs: args.workflow_id.startsWith('dedicated-') ? [data.canary] : data.history}}),
    listJobsForWorkflowRun: async () => ({data: {jobs: data.jobs, total_count: data.jobs.length}}),
  }}};
}
function setup() {
  const outputs = {}, failures = [];
  return {outputs, failures, core: {setOutput: (key, value) => {outputs[key] = value;},
    setFailed: reason => failures.push(reason), info: () => {}},
    context: {repo: {owner: 'ericson-j-santos', repo: 'desktop-pc24x7-runtime'},
      ref: 'refs/heads/' + branch, sha, runId: 100}, now: () => now};
}
test('adapter positive and negative controls use only read APIs', async () => {
  const positive = setup(); await admit({...positive, github: api(fixture())});
  assert.equal(positive.outputs.physical_ready, 'true'); assert.deepEqual(positive.failures, []);
  const data = fixture(); data.history[1].updated_at = '2026-10-14T22:59:00Z';
  const negative = setup(); await admit({...negative, github: api(data)});
  assert.equal(negative.outputs.physical_ready, 'false');
  assert.deepEqual(negative.failures, ['NEW_RUNNER_PRECONDITION_REQUIRED']);
});
test('API errors are sanitized and keep physical admission closed', async () => {
  const state = setup(), github = api(fixture());
  github.rest.repos.getBranch = async () => {throw Error('secret-marker');};
  await admit({...state, github});
  assert.equal(state.outputs.physical_ready, 'false');
  assert.deepEqual(state.failures, ['ADMISSION_READBACK_UNAVAILABLE']);
  assert.ok(!JSON.stringify(state.outputs).includes('secret-marker'));
});
function assertWorkflowBindings(workflow) {
  // Windows checkout may materialize CRLF; validate the same contract on both OSes.
  const normalized = workflow.replace(/\r\n?/g, '\n');
  for (const name of ['pickup_watchdog', 'inspect']) {
    const section = normalized.split('\n  ' + name + ':\n')[1];
    assert.ok(section, 'physical job must exist');
    const job = section.split(/\n  [a-z_]+:\n/)[0];
    assert.match(job, /needs: \[contract, admission\]/);
    assert.match(job, /needs\.admission\.outputs\.physical_ready == 'true'/);
  }
}
const workflow = () => fs.readFileSync(path.join(__dirname, '../.github/workflows/reqsys-dev-readonly-inventory.yml'), 'utf8');
test('workflow regression: both physical jobs depend on admission and hosted tests run first', () => {
  const text = workflow(); assertWorkflowBindings(text);
  assert.ok(text.includes('node --test tests/test_reqsys_dev_inventory_admission.cjs'));
  assert.ok(text.includes('await admission.admit({github, context, core})'));
});
test('Windows CRLF and Unix LF accept the same valid workflow', () => {
  const lf = workflow().replace(/\r\n?/g, '\n');
  assertWorkflowBindings(lf);
  assertWorkflowBindings(lf.replace(/\n/g, '\r\n'));
});
test('test-of-test: removing admission is rejected after a valid baseline on both OSes', () => {
  const lf = workflow().replace(/\r\n?/g, '\n');
  for (const valid of [lf, lf.replace(/\n/g, '\r\n')]) {
    assertWorkflowBindings(valid);
    const oldDependency = valid.replaceAll('needs: [contract, admission]', 'needs: contract');
    assert.throws(() => assertWorkflowBindings(oldDependency), {code: 'ERR_ASSERTION'});
  }
});
