"""Regressoes locais; nao sao evidencia de execucao fisica no Lenovo."""
from __future__ import annotations

import base64
import importlib.util
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "lenovo_inventory_api_bridge.py"
spec = importlib.util.spec_from_file_location("lenovo_bridge", SOURCE)
bridge = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(bridge)
SHA = "b038a770117e0d3d4d1297a3f4bec112ff68a744"
RUN_ID = 12345


def make_ticket(**update):
    now = datetime.now(timezone.utc)
    payload = {
        "request_id": "lenovo-request-20261114",
        "idempotency_key": "a" * 64,
        "authorized_user_id": bridge.OWNER_ID,
        "expected_sha": SHA,
        "repository": f"{bridge.OWNER}/{bridge.REPO}",
        "workflow": bridge.WORKFLOW,
        "decision": "authorize_one_readonly_inventory",
        "issued_at": (now - timedelta(seconds=3)).isoformat(),
        "expires_at": (now + timedelta(minutes=4)).isoformat(),
        "cost_zero_certified": True,
        "cost_evidence_ref": "https://github.com/ericson-j-santos/desktop-pc24x7-runtime/issues/151",
    }
    payload.update(update)
    private = Ed25519PrivateKey.generate()
    signature = private.sign(bridge.canonical(payload))
    document = {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
    public = private.public_key().public_bytes_raw()
    return document, public


def job(name, label):
    return {"name": name, "status": "completed", "conclusion": "success", "labels": [label],
            "steps": [{"name": "Unit and negative-control tests", "status": "completed", "conclusion": "success"}]}


class FakeApi:
    def __init__(self):
        self.head = SHA
        self.var = "old" * 13 + "o"
        self.runs = [{"id": 88, "head_sha": SHA, "head_branch": "main", "event": "push",
                      "status": "completed", "conclusion": "success", "run_attempt": 1}]
        self.jobs = [job("Python compile and tests", "windows-latest"),
                     job("Portable Linux compile and tests", "ubuntu-latest")]
        self.post_count = 0
        self.calls = []
        self.dispatch_response = {
            "workflow_run_id": RUN_ID,
            "html_url": f"https://github.com/{bridge.OWNER}/{bridge.REPO}/actions/runs/{RUN_ID}"}
        self.run_metadata = {"id": RUN_ID, "head_sha": SHA,
                             "event": "workflow_dispatch", "head_branch": "main",
                             "status": "completed", "conclusion": "success",
                             "actor": {"login": bridge.OWNER}}

    def call(self, method, path, data=None):
        self.calls.append((method, path, data))
        if path == "/user":
            return {"login": bridge.OWNER, "id": bridge.OWNER_ID}
        if path == bridge.BASE:
            return {"full_name": f"{bridge.OWNER}/{bridge.REPO}", "private": False}
        if path == bridge.BASE + "/branches/main":
            return {"commit": {"sha": self.head}}
        if "/actions/workflows/ci.yml/runs?" in path:
            return {"total_count": len(self.runs), "workflow_runs": self.runs}
        if path == bridge.BASE + "/actions/runs/88/jobs?per_page=100":
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        if path == bridge.BASE + "/actions/variables/" + bridge.VARIABLE:
            if method == "PATCH":
                self.var = data["value"]
                return {}
            return {"name": bridge.VARIABLE, "value": self.var}
        if path == bridge.BASE + f"/actions/workflows/{bridge.WORKFLOW}/dispatches":
            assert method == "POST"
            assert data == {"ref": "main", "return_run_details": True,
                            "inputs": {"expected_source_sha": SHA,
                                       "confirmation": bridge.CONFIRMATION}}
            self.post_count += 1
            return self.dispatch_response
        if path == bridge.BASE + f"/actions/runs/{RUN_ID}":
            return self.run_metadata
        if path == bridge.BASE + f"/actions/runs/{RUN_ID}/jobs?per_page=100":
            return {"total_count": 1, "jobs": [{"name": "inventory", "status": "completed",
                                                  "conclusion": "success", "runner_name": "DESKTOP-RP23OGS-runtime",
                                                  "runner_id": 9}]}
        raise AssertionError(f"unexpected API: {method}, {path}")


@pytest.mark.parametrize("difference", [
    {"authorized_user_id": 999},
    {"expected_sha": "f" * 40},
    {"decision": "automatic_merge"},
    {"cost_zero_certified": False},
    {"cost_evidence_ref": "file:///fake"},
    {"workflow": "other.yml"},
    {"expires_at": "2025-01-01T00:00:00+00:00"},
    {"issued_at": "2027-01-01T00:00:00+00:00"},
    {"idempotency_key": "bad"},
])
def test_ticket_rejects_wrong_contract_even_with_valid_signature(difference):
    doc, public = make_ticket(**difference)
    with pytest.raises(bridge.Blocked):
        bridge.verify_ticket(doc, public, SHA)


def test_ticket_positive_and_tampering_rejected():
    doc, public = make_ticket()
    assert bridge.verify_ticket(doc, public, SHA)["expected_sha"] == SHA
    doc["payload"]["request_id"] = "modified-request"
    with pytest.raises(bridge.Blocked, match="signature"):
        bridge.verify_ticket(doc, public, SHA)


def test_owner_main_ci_preflight_and_readback():
    api = FakeApi()
    bridge.assert_owner_and_main(api, SHA)
    assert bridge.assert_ci(api, SHA) == 88
    metadata = bridge.readback(api, RUN_ID, SHA)
    assert metadata["physical_receipt_proven"] is False
    assert metadata["runner_name"] == "DESKTOP-RP23OGS-runtime"


@pytest.mark.parametrize("mutate", [
    lambda api: setattr(api, "head", "f" * 40),
    lambda api: api.runs.clear(),
    lambda api: api.jobs.pop(),
    lambda api: api.jobs[0]["steps"].clear(),
    lambda api: api.runs[0].update({"run_attempt": 2}),
    lambda api: api.runs[0].update({"conclusion": "skipped"}),
])
def test_missing_gates_block_before_any_write(mutate):
    api = FakeApi()
    mutate(api)
    with TemporaryDirectory() as folder:
        with bridge.database(Path(folder) / "state.sqlite") as db:
            with pytest.raises(bridge.Blocked):
                bridge.execute(api, db, make_ticket()[0]["payload"], SHA)
    assert api.post_count == 0
    assert not any(m == "PATCH" for m, _, _ in api.calls)


def test_positive_dispatch_and_replay_have_one_post():
    api = FakeApi()
    ticket = make_ticket()[0]["payload"]
    with TemporaryDirectory() as folder:
        with bridge.database(Path(folder) / "state.sqlite") as db:
            first = bridge.execute(api, db, ticket, SHA)
            second = bridge.execute(api, db, ticket, SHA)
            assert first["result"] == "DISPATCH_CREATED_NOT_YET_VALIDATED"
            assert first["run_id"] == RUN_ID
            assert second["result"] == "REPLAY_SAME_RUN"
            assert first["sha"] == SHA
    assert api.var == SHA
    assert api.post_count == 1


def test_ambiguous_dispatch_never_retries_and_keeps_reservation():
    api = FakeApi()
    api.dispatch_response = {}
    ticket = make_ticket()[0]["payload"]
    with TemporaryDirectory() as folder:
        with bridge.database(Path(folder) / "state.sqlite") as db:
            with pytest.raises(bridge.Blocked, match="ambiguous"):
                bridge.execute(api, db, ticket, SHA)
            with pytest.raises(bridge.Blocked, match="reserved_or_unknown"):
                bridge.execute(api, db, ticket, SHA)
            assert db.execute("SELECT state FROM dispatches").fetchone()[0] == "reserved"
    assert api.post_count == 1


def test_variable_readback_failure_does_not_dispatch():
    api = FakeApi()
    original = api.call

    def no_update(method, path, data=None):
        if method == "PATCH":
            return {}
        return original(method, path, data)

    api.call = no_update
    with TemporaryDirectory() as folder:
        with bridge.database(Path(folder) / "state.sqlite") as db:
            with pytest.raises(bridge.Blocked, match="readback"):
                bridge.execute(api, db, make_ticket()[0]["payload"], SHA)
    assert api.post_count == 0


def test_reuse_same_key_for_new_sha_blocks():
    api = FakeApi()
    with TemporaryDirectory() as folder:
        with bridge.database(Path(folder) / "state.sqlite") as db:
            bridge.execute(api, db, make_ticket()[0]["payload"], SHA)
            with pytest.raises(bridge.Blocked, match="idempotency_key_reused"):
                bridge.reserve(db, "a" * 64, "f" * 40, "lenovo-request-20261114")


def test_on_dispatch_branch_move_blocks_after_reservation():
    api = FakeApi()
    original = api.call
    branch_calls = 0

    def moved(method, path, data=None):
        nonlocal branch_calls
        if path == bridge.BASE + "/branches/main":
            branch_calls += 1
            if branch_calls > 1:
                api.head = "f" * 40
        return original(method, path, data)

    api.call = moved
    with TemporaryDirectory() as folder:
        with bridge.database(Path(folder) / "state.sqlite") as db:
            with pytest.raises(bridge.Blocked, match="main_sha_moved"):
                bridge.execute(api, db, make_ticket()[0]["payload"], SHA)
    assert api.post_count == 0


def test_run_metadata_owner_change_is_not_approved():
    api = FakeApi()
    api.run_metadata["actor"]["login"] = "some-app[bot]"
    with pytest.raises(bridge.Blocked, match="run_identity_mismatch"):
        bridge.readback(api, RUN_ID, SHA)
