'use strict';
// Read-only admission for this Desktop inventory, not proof of runtime recovery.
const OWNER = 'ericson-j-santos';
const REPO = 'desktop-pc24x7-runtime';
const BRANCH = 'fix/reqsys-dev-runtime-readonly-inventory-20261014';
const CANARY = 'dedicated-runtime-runner-e2e.yml';
const INVENTORY = 'reqsys-dev-readonly-inventory.yml';
const RUNNER = 'DESKTOP-PDQK954-runtime';
const JOB = 'Pickup on dedicated Desktop runtime runner';
const REQUIRED_STEPS = [
  'Bootstrap governed session and runner version preflight',
  'Prove exact host, repository, runner and version through Command Gateway',
  'Upload sanitized evidence',
];
const MAX_AGE_MS = 15 * 60 * 1000;
const blocked = reason => ({ready: false, reason});
const timestamp = value => typeof value === 'string' ? Date.parse(value) : NaN;

function assess({canary, jobs, history, currentId, sha, mainSha, now}) {
  if (!Number.isFinite(now) || !/^[0-9a-f]{40}$/.test(mainSha || '') ||
      !/^[0-9a-f]{40}$/.test(sha || '') || !Number.isSafeInteger(currentId)) {
    return blocked('ADMISSION_INPUT_INVALID');
  }
  if (!canary || canary.repository?.full_name !== OWNER + '/' + REPO ||
      canary.path !== '.github/workflows/' + CANARY ||
      canary.head_branch !== 'main' || canary.head_sha !== mainSha ||
      canary.status !== 'completed' || canary.conclusion !== 'success' ||
      !Number.isSafeInteger(canary.id)) {
    return blocked('FRESH_DEDICATED_CANARY_REQUIRED');
  }
  if (!Array.isArray(jobs)) return blocked('CANARY_JOBS_UNVERIFIED');
  const matches = jobs.filter(job => job?.name === JOB);
  if (matches.length !== 1) return blocked('CANARY_JOB_NOT_UNIQUE');
  const job = matches[0];
  if (job.run_id !== canary.id || job.head_sha !== mainSha ||
      job.runner_name !== RUNNER || !Number.isSafeInteger(job.runner_id) || job.runner_id <= 0 ||
      job.status !== 'completed' || job.conclusion !== 'success') {
    return blocked('DEDICATED_PICKUP_NOT_VERIFIED');
  }
  const started = timestamp(job.started_at), completed = timestamp(job.completed_at);
  if (!Number.isFinite(started) || !Number.isFinite(completed) ||
      started > completed || completed > now || now - completed > MAX_AGE_MS) {
    return blocked('CANARY_EVIDENCE_STALE_OR_INVALID');
  }
  if (!Array.isArray(job.steps) || !REQUIRED_STEPS.every(name => {
    const steps = job.steps.filter(step => step.name === name);
    return steps.length === 1 && steps[0].status === 'completed' && steps[0].conclusion === 'success';
  })) return blocked('CANARY_REQUIRED_STEP_NOT_EXECUTED');
  if (!Array.isArray(history)) return blocked('INVENTORY_HISTORY_UNVERIFIED');
  const current = history.filter(run => run?.id === currentId);
  if (current.length !== 1 || current[0].head_sha !== sha ||
      current[0].head_branch !== BRANCH || current[0].run_attempt !== 1) {
    return blocked('INVENTORY_IDENTITY_OR_REPLAY_BLOCKED');
  }
  // One inventory attempt per fresh canary. A push or rerun is not a new precondition.
  for (const run of history) {
    if (run.id === currentId) continue;
    const observed = timestamp(run.updated_at);
    if (run.path !== '.github/workflows/' + INVENTORY || run.head_branch !== BRANCH ||
        !Number.isFinite(observed) || observed > now) return blocked('INVENTORY_HISTORY_INVALID');
    if (run.status !== 'completed' || observed >= started) {
      return blocked('NEW_RUNNER_PRECONDITION_REQUIRED');
    }
  }
  return {ready: true, reason: 'FRESH_DEDICATED_PICKUP_VERIFIED', canary_run_id: canary.id};
}

async function admit({github, context, core, now = () => Date.now()}) {
  core.setOutput('physical_ready', 'false');
  if (context?.repo?.owner !== OWNER || context?.repo?.repo !== REPO ||
      context.ref !== 'refs/heads/' + BRANCH || !/^[0-9a-f]{40}$/.test(context.sha || '') ||
      !Number.isSafeInteger(context.runId) || context.runId < 1) {
    core.setFailed('ADMISSION_SCOPE_INVALID'); return blocked('ADMISSION_SCOPE_INVALID');
  }
  let result;
  try {
    const args = {owner: OWNER, repo: REPO};
    const {data: main} = await github.rest.repos.getBranch({...args, branch: 'main'});
    const {data: candidates} = await github.rest.actions.listWorkflowRuns({
      ...args, workflow_id: CANARY, branch: 'main', per_page: 1,
    });
    const canary = candidates.workflow_runs?.[0];
    if (!canary) result = blocked('FRESH_DEDICATED_CANARY_REQUIRED');
    else {
      const {data: evidence} = await github.rest.actions.listJobsForWorkflowRun({
        ...args, run_id: canary.id, filter: 'latest', per_page: 100,
      });
      const {data: previous} = await github.rest.actions.listWorkflowRuns({
        ...args, workflow_id: INVENTORY, branch: BRANCH, per_page: 20,
      });
      if (!Array.isArray(evidence.jobs) || evidence.total_count !== evidence.jobs.length) {
        result = blocked('CANARY_JOBS_INCOMPLETE');
      } else {
        result = assess({canary, jobs: evidence.jobs, history: previous.workflow_runs,
          currentId: context.runId, sha: context.sha, mainSha: main.commit?.sha, now: now()});
      }
    }
  } catch (_error) {
    result = blocked('ADMISSION_READBACK_UNAVAILABLE');
  }
  if (!result.ready) { core.setFailed(result.reason); return result; }
  core.setOutput('physical_ready', 'true');
  core.setOutput('canary_run_id', String(result.canary_run_id));
  core.info('Admission only: inventory, database and runtime E2E remain unverified.');
  return result;
}
module.exports = {assess, admit, REQUIRED_STEPS};
