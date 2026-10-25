"""Execute real admission JavaScript against local fakes; never dispatch a job."""
import json
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github/workflows/dedicated-runtime-runner-e2e.yml"
ADMISSION = "Admit fixed inventory from reviewed current main and successful native CI"
PICKUP = "Reject stale native pickup before checkout or bootstrap"
HARNESS = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const outputs = {};
let jobsCall = 0;
const sandbox = {
  context: input.context,
  inputs: input.inputs,
  fromJSON: JSON.parse,
  format: (template, ...args) => template.replace(/\{(\d+)\}/g, (_, i) => args[Number(i)]),
  process: {env: input.env},
  core: {setOutput: (k, v) => {outputs[k] = v;}},
  github: {run_id: input.run_id, ref: input.ref, rest: {
    repos: {getBranch: async () => ({data: {commit: {sha: input.main_sha}}})},
    actions: {
      listWorkflowRuns: async () => ({data: {workflow_runs: input.runs}}),
      listJobsForWorkflowRun: async () => ({data: input.jobs_sequence
        ? input.jobs_sequence[Math.min(jobsCall++, input.jobs_sequence.length - 1)]
        : input.jobs}),
    },
  }},
  require: name => {
    if (name !== 'os') throw new Error('MODULE_FORBIDDEN');
    return {hostname: () => input.host};
  },
  setTimeout: callback => callback(),
  Date: class extends Date {
    static now() { return input.now_ms === undefined ? Date.now() : input.now_ms; }
  },
};
(async () => {
  try {
    await vm.runInNewContext('(async () => {\n' + input.source + '\n})()', sandbox, {timeout: 1000});
    process.stdout.write(JSON.stringify({ok: true, outputs}));
  } catch (error) {
    process.stdout.write(JSON.stringify({ok: false, reason: error.message, outputs}));
  }
})();
"""


def javascript_step(name):
    text = WORKFLOW.read_text(encoding="utf-8")
    marker = "      - name: " + name + "\n"
    if text.count(marker) != 1:
        raise AssertionError("Expected one fixed workflow step")
    block = text.split(marker, 1)[1].split("\n      - name:", 1)[0]
    body = block.split("          script: |\n", 1)[1].rstrip()
    return "\n".join(line[12:] if line.strip() else "" for line in body.splitlines())


def fixture():
    sha = "a" * 40
    return {
        "context": {"eventName": "workflow_dispatch", "actor": "ericson-j-santos",
                    "repo": {"owner": "ericson-j-santos", "repo": "desktop-pc24x7-runtime"},
                    "ref": "refs/heads/main", "sha": sha},
        "env": {"INVENTORY_SOURCE_SHA": sha, "GITHUB_RUN_ATTEMPT": "1",
                "RUNNER_NAME": "DESKTOP-PDQK954-runtime"},
        "host": "DESKTOP-PDQK954", "main_sha": sha,
        "runs": [{"id": 1, "head_sha": sha, "head_branch": "main", "event": "push",
                  "conclusion": "success",
                  "repository": {"full_name": "ericson-j-santos/desktop-pc24x7-runtime"}}],
        "jobs": {"total_count": 2, "jobs": [
            {"name": name, "run_id": 1, "status": "completed", "conclusion": "success",
             "runner_id": 0, "started_at": "2026-10-24T17:29:30Z",
             "completed_at": "2026-10-24T17:30:00Z",
             "labels": ["windows-latest"] if name == "Python compile and tests"
                       else ["ubuntu-latest"],
             "steps": [{"name": "Unit and negative-control tests", "status": "completed",
                        "conclusion": "success"}]}
            for name in ("Python compile and tests", "Portable Linux compile and tests")
        ]},
    }



def pickup_fixture(age_ms=0):
    data = fixture()
    data["now_ms"] = 1_800_000_000_000
    data["env"]["INVENTORY_ADMITTED_AT"] = datetime.fromtimestamp(
        (data["now_ms"] - age_ms) / 1000, timezone.utc,
    ).isoformat()
    return data

def execute(data, step=ADMISSION, source=None):
    node = shutil.which("node")
    if not node:
        raise AssertionError("Node.js required; do not skip real admission contract tests")
    data = {**data, "source": javascript_step(step) if source is None else source}
    with tempfile.TemporaryDirectory(prefix="native-inventory-contract-") as folder:
        harness = Path(folder) / "harness.cjs"
        harness.write_text(HARNESS, encoding="utf-8")
        completed = subprocess.run([node, str(harness)], input=json.dumps(data),
                                   text=True, capture_output=True, timeout=10, check=False)
    if completed.returncode != 0:
        raise AssertionError("Local admission harness failed")
    return json.loads(completed.stdout)


class NativeInventoryWorkflowTests(unittest.TestCase):
    def test_exact_native_ci_admitted(self):
        result = execute(fixture())
        self.assertTrue(result["ok"])
        self.assertIn("admitted_at", result["outputs"])

    def test_wrong_owner_repo_event_ref_or_actor_rejected(self):
        for key, value in (("eventName", "push"), ("actor", "other"), ("ref", "refs/heads/other"),
                           ("repo", {"owner": "other", "repo": "desktop-pc24x7-runtime"})):
            data = fixture()
            data["context"][key] = value
            self.assertFalse(execute(data)["ok"])

    def test_bad_source_sha_rejected(self):
        for value in ("a" * 39, "b" * 40, "main", ""):
            data = fixture()
            data["env"]["INVENTORY_SOURCE_SHA"] = value
            self.assertFalse(execute(data)["ok"])

    def test_main_movement_rejected(self):
        data = fixture()
        data["main_sha"] = "b" * 40
        self.assertFalse(execute(data)["ok"])

    def test_no_ci_rejected(self):
        data = fixture()
        data["runs"] = []
        self.assertFalse(execute(data)["ok"])

    def test_wrong_ci_sha_event_branch_or_result_rejected(self):
        for key, value in (("head_sha", "b" * 40), ("event", "pull_request"),
                           ("head_branch", "other"), ("conclusion", "failure")):
            data = fixture()
            data["runs"][0][key] = value
            self.assertFalse(execute(data)["ok"])

    def test_skipped_or_unexecuted_hosted_job_rejected(self):
        for key, value in (("conclusion", "skipped"), ("status", "queued"),
                           ("started_at", None), ("completed_at", None)):
            data = fixture()
            data["jobs"]["jobs"][0][key] = value
            self.assertFalse(execute(data)["ok"])

    def test_wrong_hosted_ci_identity_rejected(self):
        for key, value in (("run_id", 2), ("labels", ["self-hosted"])):
            data = fixture()
            data["jobs"]["jobs"][0][key] = value
            self.assertFalse(execute(data)["ok"])

    def test_transient_hosted_ci_metadata_is_retried(self):
        data = fixture()
        incomplete = json.loads(json.dumps(data["jobs"]))
        incomplete["jobs"][0]["labels"] = []
        data["jobs_sequence"] = [incomplete, data["jobs"]]
        self.assertTrue(execute(data)["ok"])

    def test_skipped_test_step_rejected(self):
        data = fixture()
        data["jobs"]["jobs"][0]["steps"][0]["conclusion"] = "skipped"
        self.assertFalse(execute(data)["ok"])

    def test_incomplete_job_page_rejected(self):
        data = fixture()
        data["jobs"]["total_count"] = 101
        self.assertFalse(execute(data)["ok"])

    def test_rerun_rejected(self):
        data = fixture()
        data["env"]["GITHUB_RUN_ATTEMPT"] = "2"
        self.assertFalse(execute(data)["ok"])

    def test_stale_pickup_rejected_before_bootstrap(self):
        data = fixture()
        data["env"]["INVENTORY_ADMITTED_AT"] = "2000-01-01T00:00:00Z"
        self.assertFalse(execute(data, PICKUP)["ok"])
        raw = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(raw.index(PICKUP), raw.index("Checkout exact runtime SHA"))

    def test_manual_only_fixed_modes_and_no_free_command(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        trigger = raw.split("\npermissions:", 1)[0]
        self.assertIn("default: runner-identity", trigger)
        self.assertIn("options: [runner-identity, native-postgres-inventory, native-postgres-readback]", trigger)
        for forbidden in ("\n  push:", "\n  schedule:", "\n  pull_request:", "\n      command:",
                          "\n      host:", "\n      path:", "\n      url:"):
            self.assertNotIn(forbidden, trigger)

    def test_gateway_and_session_preserved(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        native = raw.split("      - name: Read fixed native PostgreSQL metadata", 1)[1]
        native = native.split("\n      - name:", 1)[0]
        self.assertNotIn("native_windows_pg_readback.py", native)
        for required in ("command_gateway.py", '"--risk", "1"', '"--expected-head"',
                         '"--session-id"', '"--timeout", "60"', '"python", "-B", $script'):
            self.assertIn(required, native)
        self.assertIn("--require-runner-version-preflight", raw)
        self.assertIn('throw "SESSION_LAUNCH_BLOCKED"', raw)
        self.assertNotIn("native_windows_pg_inventory.py --", raw)

    def test_native_mode_cannot_cancel_other_work(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("format('native-pg-inventory-954-{0}', github.run_id)", raw)
        self.assertIn("cancel-in-progress: $" + "{{ (inputs.diagnostic != 'native-postgres-inventory' && inputs.diagnostic != 'native-postgres-readback') }}", raw)
        cancel = raw.split("      - name: Fail closed and cancel stalled canary", 1)[1]
        self.assertIn("if: steps.watchdog.outcome == 'failure' && (inputs.diagnostic != 'native-postgres-inventory' && inputs.diagnostic != 'native-postgres-readback')", cancel)
        self.assertIn("NATIVE_INVENTORY_PICKUP_EXPIRED_NO_COLLECTION_ALLOWED", raw)

    def test_native_groups_are_unique_and_legacy_behavior_is_unchanged(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        block = raw.split("\nconcurrency:\n", 1)[1].split("\njobs:", 1)[0]
        group, cancel = [line.split(": ", 1)[1].strip()[3:-2].strip()
                         for line in block.strip().splitlines()]
        source = ("core.setOutput('group', (" + group + "));"
                  "core.setOutput('cancel', (" + cancel + "));")
        results = []
        for run_id in ("100", "101"):
            data = {**fixture(), "inputs": {"diagnostic": "native-postgres-inventory"},
                    "run_id": run_id, "ref": "refs/heads/main"}
            output = execute(data, source=source)
            self.assertTrue(output["ok"])
            self.assertIs(output["outputs"]["cancel"], False)
            results.append(output["outputs"]["group"])
        self.assertEqual(results, ["native-pg-inventory-954-100", "native-pg-inventory-954-101"])
        data["inputs"]["diagnostic"] = "runner-identity"
        output = execute(data, source=source)
        self.assertEqual(output["outputs"]["group"],
                         "dedicated-runtime-runner-e2e-refs/heads/main")
        self.assertIs(output["outputs"]["cancel"], True)

    def test_same_input_replay_does_not_dispatch(self):
        first, second = execute(fixture()), execute(fixture())
        self.assertTrue(first["ok"] and second["ok"])
        body = javascript_step(ADMISSION)
        for mutation in ("createWorkflowDispatch", "cancelWorkflowRun", "update", "createRef"):
            self.assertNotIn(mutation, body)

    def test_native_artifact_local_only_and_no_storage_charge_assumption(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("artifacts/native-pg-inventory/evidence.json", raw)
        upload = raw.split("      - name: Upload sanitized evidence", 1)[1].split("  queue_watchdog:", 1)[0]
        self.assertIn("if: always() && (inputs.diagnostic != 'native-postgres-inventory' && inputs.diagnostic != 'native-postgres-readback')", upload)

    def test_native_inventory_routing_requires_exact_desktop_identity_label(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        job = raw.split("\n  e2e:\n", 1)[1].split("\n  queue_watchdog:\n", 1)[0]
        line = next(line.strip() for line in job.splitlines()
                    if line.strip().startswith("runs-on:"))
        expression = line.split(": ", 1)[1][3:-2].strip()
        data = {**fixture(), "inputs": {"diagnostic": "native-postgres-inventory"}}
        output = execute(data, source="core.setOutput('labels', (" + expression + "));")
        self.assertTrue(output["ok"])
        self.assertEqual(output["outputs"]["labels"],
                         ["self-hosted", "Windows", "X64", "pc24x7",
                          "desktop-runtime", "runtime-dev", "desktop-pdqk954"])

    def test_non_native_routing_preserves_all_legacy_labels(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        job = raw.split("\n  e2e:\n", 1)[1].split("\n  queue_watchdog:\n", 1)[0]
        line = next(line.strip() for line in job.splitlines()
                    if line.strip().startswith("runs-on:"))
        expression = line.split(": ", 1)[1][3:-2].strip()
        for mode in ("runner-identity", "", "unexpected-mode"):
            data = {**fixture(), "inputs": {"diagnostic": mode}}
            output = execute(data, source="core.setOutput('labels', (" + expression + "));")
            self.assertTrue(output["ok"])
            self.assertEqual(output["outputs"]["labels"],
                             ["self-hosted", "Windows", "X64", "pc24x7",
                              "desktop-runtime", "runtime-dev", "desktop-pdqk954"])

    def test_fresh_exact_native_runner_and_host_pass_pickup_guard(self):
        self.assertTrue(execute(pickup_fixture(), PICKUP)["ok"])

    def test_wrong_runner_or_host_rejected_before_checkout(self):
        for runner, host in (("other-runtime", "DESKTOP-PDQK954"),
                             ("DESKTOP-PDQK954-runtime", "OTHER-HOST")):
            data = pickup_fixture()
            data["env"]["RUNNER_NAME"] = runner
            data["host"] = host
            self.assertFalse(execute(data, PICKUP)["ok"])

    def test_missing_invalid_or_future_pickup_time_rejected(self):
        future = pickup_fixture(age_ms=-1)["env"]["INVENTORY_ADMITTED_AT"]
        for admitted_at in ("", "invalid-time", future):
            data = pickup_fixture()
            data["env"]["INVENTORY_ADMITTED_AT"] = admitted_at
            self.assertFalse(execute(data, PICKUP)["ok"])

    def test_pickup_ttl_boundary_is_not_relaxed(self):
        self.assertTrue(execute(pickup_fixture(age_ms=300_000), PICKUP)["ok"])
        self.assertFalse(execute(pickup_fixture(age_ms=300_001), PICKUP)["ok"])

    def test_identity_guard_is_first_native_step_and_cannot_be_ignored(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        job = raw.split("\n  e2e:\n", 1)[1].split("\n  queue_watchdog:\n", 1)[0]
        steps = job.split("    steps:\n", 1)[1]
        self.assertTrue(steps.startswith("      - name: " + PICKUP + "\n"))
        guard = steps.split("\n      - name:", 1)[0]
        self.assertIn("if: (inputs.diagnostic == 'native-postgres-inventory' || inputs.diagnostic == 'native-postgres-readback')", guard)
        self.assertNotIn("continue-on-error", guard)
        self.assertIn("process.env.RUNNER_NAME !== 'DESKTOP-PDQK954-runtime'", guard)
        self.assertIn("hostname().toUpperCase() !== 'DESKTOP-PDQK954'", guard)
        self.assertIn("age > 300000", guard)
        self.assertNotIn("permissions:", job)
        self.assertNotIn("listSelfHostedRunners", raw)

    def test_readback_identity_label_excludes_other_host_with_shared_runtime_labels(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        job = raw.split("\n  e2e:\n", 1)[1].split("\n  queue_watchdog:\n", 1)[0]
        line = next(line.strip() for line in job.splitlines()
                    if line.strip().startswith("runs-on:"))
        expression = line.split(": ", 1)[1][3:-2].strip()
        data = {**fixture(), "inputs": {"diagnostic": "native-postgres-readback"}}
        output = execute(data, source="core.setOutput('labels', (" + expression + "));")
        self.assertTrue(output["ok"])
        self.assertEqual(output["outputs"]["labels"],
                         ["self-hosted", "Windows", "X64", "pc24x7",
                          "desktop-runtime", "runtime-dev", "desktop-pdqk954"])
        common = {"self-hosted", "Windows", "X64", "pc24x7", "desktop-runtime", "runtime-dev"}
        registry = {2: common | {"desktop-pdqk954"}, 24: common | {"desktop-rp23ogs"}}
        required = set(output["outputs"]["labels"])
        self.assertEqual([runner_id for runner_id, labels in registry.items()
                          if required <= labels], [2])
        # Negative control: the prior six-label selector admits both hosts.
        self.assertEqual([runner_id for runner_id, labels in registry.items()
                          if common <= labels], [2, 24])
        # Losing the identity label must not silently fall back to the other PC.
        registry[2] = common
        self.assertEqual([runner_id for runner_id, labels in registry.items()
                          if required <= labels], [])


    def test_every_mode_selects_exactly_one_fixed_gateway_payload(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        names = ("Prove exact host, repository, runner and version through Command Gateway",
                 "Read fixed native PostgreSQL metadata through Command Gateway",
                 "Read fixed PostgreSQL listener owners and legacy receipts through Command Gateway")
        for mode, expected in (("runner-identity", 0), ("native-postgres-inventory", 1),
                               ("native-postgres-readback", 2)):
            enabled = []
            for index, name in enumerate(names):
                block = raw.split("      - name: " + name + "\n", 1)[1].split("\n      - name:", 1)[0]
                condition = next(line.strip()[4:] for line in block.splitlines()
                                 if line.strip().startswith("if: "))
                data = {**fixture(), "inputs": {"diagnostic": mode}}
                output = execute(data, source="core.setOutput('enabled', (" + condition + "));")
                self.assertTrue(output["ok"])
                if output["outputs"]["enabled"]:
                    enabled.append(index)
            self.assertEqual(enabled, [expected])

    def test_readback_has_no_cancellation_or_artifact_upload(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        for name in ("Upload sanitized evidence", "Fail closed and cancel stalled canary"):
            block = raw.split("      - name: " + name + "\n", 1)[1].split("\n      - name:", 1)[0]
            self.assertIn("inputs.diagnostic != 'native-postgres-inventory'", block)
            self.assertIn("inputs.diagnostic != 'native-postgres-readback'", block)

    def test_readback_shares_admission_first_guard_and_fixed_gateway_only(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        for name in (ADMISSION, PICKUP):
            block = raw.split("      - name: " + name + "\n", 1)[1].split("\n      - name:", 1)[0]
            condition = next(line.strip()[4:] for line in block.splitlines()
                             if line.strip().startswith("if: "))
            for mode in ("native-postgres-inventory", "native-postgres-readback"):
                output = execute({**fixture(), "inputs": {"diagnostic": mode}},
                                 source="core.setOutput('enabled', (" + condition + "));")
                self.assertTrue(output["outputs"]["enabled"])
        block = raw.split("      - name: Read fixed PostgreSQL listener owners", 1)[1]
        block = block.split("      - name: Upload sanitized evidence", 1)[0]
        for required in ("native_windows_pg_readback.py", "command_gateway.py",
                         '"--risk", "1"', '"--expected-head"', '"--session-id"',
                         '"--timeout", "60"', '"python", "-B", $script'):
            self.assertIn(required, block)
        for forbidden in ("inputs.command", "inputs.path", "inputs.host", "native_windows_pg_readback.py --"):
            self.assertNotIn(forbidden, block)

    def test_readback_concurrency_is_unique_and_cannot_cancel(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        block = raw.split("\nconcurrency:\n", 1)[1].split("\njobs:", 1)[0]
        group, cancel = [line.split(": ", 1)[1].strip()[3:-2].strip()
                         for line in block.strip().splitlines()]
        data = {**fixture(), "inputs": {"diagnostic": "native-postgres-readback"},
                "run_id": "102", "ref": "refs/heads/main"}
        output = execute(data, source=("core.setOutput('group', (" + group + "));"
                                       "core.setOutput('cancel', (" + cancel + "));"))
        self.assertEqual(output["outputs"]["group"], "native-pg-inventory-954-102")
        self.assertIs(output["outputs"]["cancel"], False)


if __name__ == "__main__":
    unittest.main()

