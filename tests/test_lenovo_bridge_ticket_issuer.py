"""Independent receipt test. No physical access or production signing keys."""
from __future__ import annotations

import base64
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "lenovo_bridge_ticket_issuer.py"
spec = importlib.util.spec_from_file_location("lenovo_ticket_issuer", SCRIPT)
issuer = importlib.util.module_from_spec(spec)
assert spec.loader
sys.path.insert(0, str(SCRIPT.parent))
try:
    spec.loader.exec_module(issuer)
finally:
    sys.path.remove(str(SCRIPT.parent))

SHA = "a" * 40
NOW = datetime(2026, 11, 14, 19, 0, tzinfo=timezone.utc)


def inputs():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    base = {
        "request_id": "lenovo-ticket-123", "idempotency_key": "b" * 64,
        "expected_sha": SHA,
        "repository": "ericson-j-santos/desktop-pc24x7-runtime",
        "workflow": "lenovo-installed-inventory-readonly.yml",
        "issued_at": (NOW - timedelta(seconds=10)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
    }
    owner = dict(base, kind="owner-authorization.v1", authorized_user_id=issuer.bridge.OWNER_ID,
                 decision="authorize_one_readonly_inventory")
    cost = dict(base, kind="independent-cost-zero.v1", cost_zero_certified=True,
                cost_evidence_ref="https://github.com/ericson-j-santos/desktop-pc24x7-runtime/issues/151",
                evidence_sha256="c" * 64, currency="BRL", incremental_cost_max=0)
    def sign(key, payload):
        return {"payload": payload,
                "signature": base64.b64encode(key.sign(issuer.bridge.canonical(payload))).decode()}
    return keys, sign(keys[0], owner), sign(keys[1], cost), sign


def test_valid_distinct_signed_receipts_issue_bridge_verifiable_ticket():
    keys, owner, cost, _ = inputs()
    doc = issuer.issue_ticket(owner, cost, owner_public=keys[0].public_key().public_bytes_raw(),
                              cost_public=keys[1].public_key().public_bytes_raw(),
                              signing_key=keys[2], sha=SHA, now=NOW)
    verified = issuer.bridge.verify_ticket(doc, keys[2].public_key().public_bytes_raw(), SHA, now=NOW)
    assert verified["expected_sha"] == SHA
    assert verified["cost_zero_certified"] is True
    assert verified["expires_at"] == (NOW + timedelta(minutes=5)).isoformat()


@pytest.mark.parametrize("change", [
    lambda o, c: c["payload"].update(cost_zero_certified=False),
    lambda o, c: c["payload"].update(incremental_cost_max=0.01),
    lambda o, c: c["payload"].update(cost_evidence_ref="https://evil.example/ref"),
    lambda o, c: c["payload"].update(evidence_sha256="invalid"),
    lambda o, c: c["payload"].update(expected_sha="f" * 40),
    lambda o, c: o["payload"].update(authorized_user_id=0),
    lambda o, c: o["payload"].update(expires_at="2025-01-01T00:00:00+00:00"),
    lambda o, c: o["payload"].update(issued_at="2027-01-01T00:00:00+00:00"),
    lambda o, c: c.update(signature="invalid"),
])
def test_invalid_or_tampered_receipts_fail_closed(change):
    keys, owner, cost, _ = inputs()
    change(owner, cost)
    with pytest.raises(issuer.bridge.Blocked):
        issuer.issue_ticket(owner, cost, owner_public=keys[0].public_key().public_bytes_raw(),
                            cost_public=keys[1].public_key().public_bytes_raw(),
                            signing_key=keys[2], sha=SHA, now=NOW)


def test_cannot_self_certify_owner_and_cost():
    keys, owner, cost, _ = inputs()
    with pytest.raises(issuer.bridge.Blocked, match="independent_authorities"):
        issuer.issue_ticket(owner, cost, owner_public=keys[0].public_key().public_bytes_raw(),
                            cost_public=keys[0].public_key().public_bytes_raw(),
                            signing_key=keys[2], sha=SHA, now=NOW)


def test_signed_cost_from_wrong_request_blocks():
    keys, owner, cost, sign = inputs()
    cost["payload"]["request_id"] = "different-request"
    cost = sign(keys[1], cost["payload"])
    with pytest.raises(issuer.bridge.Blocked, match="scope_disagreement"):
        issuer.issue_ticket(owner, cost, owner_public=keys[0].public_key().public_bytes_raw(),
                            cost_public=keys[1].public_key().public_bytes_raw(),
                            signing_key=keys[2], sha=SHA, now=NOW)


def test_ticket_scope_expires_early_of_owner_or_cost():
    keys, owner, cost, sign = inputs()
    cost["payload"]["expires_at"] = (NOW + timedelta(minutes=2)).isoformat()
    cost = sign(keys[1], cost["payload"])
    doc = issuer.issue_ticket(owner, cost, owner_public=keys[0].public_key().public_bytes_raw(),
                              cost_public=keys[1].public_key().public_bytes_raw(),
                              signing_key=keys[2], sha=SHA, now=NOW)
    assert doc["payload"]["expires_at"] == (NOW + timedelta(minutes=2)).isoformat()
