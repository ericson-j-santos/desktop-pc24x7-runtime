'use strict';
// Read-only retry evidence. No dispatch, cancellation, host or database mutation.
const OWNER = 'ericson-j-santos';
const REPO = 'desktop-pc24x7-runtime';
const BRANCH = 'fix/reqsys-dev-runtime-readonly-inventory-20261014';
const PATH = '.github/workflows/reqsys-dev-readonly-inventory.yml';
const CONTRACT = 'Validate read-only collector and resolve ReqSys main';
const ADMISSION = 'Require a new verified Desktop runner precondition';
const PHYSICAL = [
  'Inspect only owned ReqSys DEV runtime metadata',
  'Abort blocked physical inventory after 300 seconds',
];
const CONTRACT_STEPS = [
  'Checkout exact runtime source',
  'Resolve exact ReqSys main SHA',
  'Setup Python 3.12',
  'Execute positive, negative and privacy controls',
  'Test request-bound diagnostic and anti-replay controls',
  'Test pre-dispatch admission before any physical job',
];
const stamp = value => typeof value === 'string' ? Date.parse(value) : NaN;
const positive = value => Number.isSafeInteger(value) && value > 0;
const deny = reason => ({ready: false, reason});
const one = (items, name) => {
  if (!Array.isArray(items)) return null;
  const found = items.filter(item => item && item.name === name);
  return found.length === 1 ? found[0] : null;
};
function identity(run, id, sha, attempt) {
  return run && run.id === id && run.head_sha === sha && run.head_branch === BRANCH &&
    run.path === PATH && run.repository?.full_name === OWNER + '/' + REPO &&
    run.event === 'push' && run.run_attempt === attempt;
}
function jobIdentity(job, id, sha, attempt) {
  return job && positive(job.id) && job.run_id === id && job.head_sha === sha &&
    job.run_attempt === attempt;
}
function during(start, end, lower, upper) {
  const a = stamp(start), b = stamp(end);
  return Number.isFinite(a) && Number.isFinite(b) && a >= lower && a <= b && b <= upper;
}
function verifyRetry({current, canary, pickup, evidence, now}) {
  const attempt = current?.run_attempt;
  if (!positive(attempt) || attempt < 2 || attempt > 50 || !evidence ||
      !Number.isFinite(now) || !positive(current?.id) ||
      !/^[0-9a-f]{40}$/.test(current?.head_sha || '')) return deny('RETRY_EVIDENCE_REQUIRED');
  const run = evidence.current;
  if (!identity(run, current.id, current.head_sha, attempt) ||
      run.status !== 'in_progress' || run.conclusion != null) return deny('RETRY_IDENTITY_INVALID');
  const started = stamp(run.run_started_at);
  const canaryCreated = stamp(canary?.created_at);
  const pickupStart = stamp(pickup?.started_at), pickupEnd = stamp(pickup?.completed_at);
  if (canary?.run_attempt !== 1 || canary?.event !== 'workflow_dispatch' ||
      ![started, canaryCreated, pickupStart, pickupEnd].every(Number.isFinite) ||
      canaryCreated > pickupStart || pickupStart > pickupEnd || pickupEnd > started ||
      started > now || now - pickupEnd > 900000) return deny('NEW_CANARY_BEFORE_RETRY_REQUIRED');
  if (!Array.isArray(evidence.previous) || evidence.previous.length !== attempt - 1) {
    return deny('RETRY_ATTEMPT_HISTORY_INCOMPLETE');
  }
  for (let index = 0; index < evidence.previous.length; index++) {
    const entry = evidence.previous[index], number = index + 1, prior = entry?.run;
    if (!identity(prior, current.id, current.head_sha, number) ||
        prior.status !== 'completed' || prior.conclusion !== 'failure') {
      return deny('RETRY_PREVIOUS_ATTEMPT_INVALID');
    }
    const previousStart = stamp(prior.run_started_at), previousEnd = stamp(prior.updated_at);
    if (![previousStart, previousEnd].every(Number.isFinite) || previousStart > previousEnd ||
        previousEnd >= canaryCreated) return deny('RETRY_REQUIRES_NEWER_CANARY');
    const failed = one(entry.jobs, ADMISSION);
    if (!jobIdentity(failed, current.id, current.head_sha, number) ||
        failed.status !== 'completed' || failed.conclusion !== 'failure' ||
        !during(failed.started_at, failed.completed_at, previousStart, previousEnd)) {
      return deny('RETRY_NOT_ADMISSION_ONLY_FAILURE');
    }
    for (const name of PHYSICAL) {
      const job = one(entry.jobs, name);
      if (!jobIdentity(job, current.id, current.head_sha, number) ||
          job.status !== 'completed' || job.conclusion !== 'skipped' ||
          job.runner_id != null || job.runner_name != null ||
          !Array.isArray(job.steps) || job.steps.length !== 0) {
        return deny('RETRY_PREVIOUS_PHYSICAL_ATTEMPT_BLOCKED');
      }
    }
  }
  const contract = one(evidence.jobs, CONTRACT);
  if (!jobIdentity(contract, current.id, current.head_sha, attempt) ||
      contract.status !== 'completed' || contract.conclusion !== 'success' ||
      !during(contract.started_at, contract.completed_at, started, now) ||
      !CONTRACT_STEPS.every(name => {
        const step = one(contract.steps, name);
        return step && step.status === 'completed' && step.conclusion === 'success' &&
          during(step.started_at, step.completed_at, stamp(contract.started_at), stamp(contract.completed_at));
      })) return deny('FRESH_CONTRACT_FOR_THIS_ATTEMPT_REQUIRED');
  if (evidence.inventory_artifacts_absent !== true) return deny('RETRY_EXISTING_INVENTORY_ARTIFACT');
  return {ready: true, reason: 'ADMISSION_ONLY_RETRY_VERIFIED'};
}
async function readHistory(github, args) {
  const runs = [], ids = new Set();
  let total = null;
  for (let page = 1; page <= 10; page++) {
    const {data} = await github.rest.actions.listWorkflowRuns({
      ...args, workflow_id: 'reqsys-dev-readonly-inventory.yml', branch: BRANCH,
      per_page: 100, page, request: {timeout: 5000},
    });
    if (!Array.isArray(data?.workflow_runs) || !Number.isSafeInteger(data.total_count) ||
        data.total_count < 1 || data.total_count > 1000 ||
        (total !== null && total !== data.total_count)) throw new Error('INVENTORY_HISTORY_INCOMPLETE');
    total = data.total_count;
    for (const run of data.workflow_runs) {
      if (!positive(run?.id) || ids.has(run.id)) throw new Error('INVENTORY_HISTORY_INVALID');
      ids.add(run.id); runs.push(run);
    }
    if (runs.length === total) return runs;
    if (runs.length > total || data.workflow_runs.length !== 100) throw new Error('INVENTORY_HISTORY_INCOMPLETE');
  }
  throw new Error('INVENTORY_HISTORY_INCOMPLETE');
}
async function readRetryEvidence(github, args, current) {
  if (!positive(current?.run_attempt) || current.run_attempt < 2 || current.run_attempt > 50) {
    throw new Error('RETRY_ATTEMPT_INVALID');
  }
  async function read(number) {
    const parameters = {...args, run_id: current.id, attempt_number: number, request: {timeout: 5000}};
    const {data: run} = await github.rest.actions.getWorkflowRunAttempt(parameters);
    const {data} = await github.rest.actions.listJobsForWorkflowRunAttempt({...parameters, per_page: 100});
    if (!Array.isArray(data?.jobs) || data.total_count !== data.jobs.length) {
      throw new Error('RETRY_JOBS_INCOMPLETE');
    }
    return {run, jobs: data.jobs};
  }
  const latest = await read(current.run_attempt), previous = [];
  for (let number = 1; number < current.run_attempt; number++) previous.push(await read(number));
  const {data: artifacts} = await github.rest.actions.listWorkflowRunArtifacts({
    ...args, run_id: current.id, per_page: 100, request: {timeout: 5000},
  });
  if (!Array.isArray(artifacts?.artifacts) || artifacts.total_count !== artifacts.artifacts.length) {
    throw new Error('RETRY_ARTIFACT_HISTORY_INCOMPLETE');
  }
  const prefix = 'reqsys-dev-readonly-inventory-' + current.id;
  return {current: latest.run, jobs: latest.jobs, previous,
    inventory_artifacts_absent: !artifacts.artifacts.some(item =>
      typeof item?.name !== 'string' || item.name === prefix || item.name.startsWith(prefix + '-'))};
}
module.exports = {verifyRetry, readHistory, readRetryEvidence, CONTRACT, ADMISSION, PHYSICAL, CONTRACT_STEPS};
