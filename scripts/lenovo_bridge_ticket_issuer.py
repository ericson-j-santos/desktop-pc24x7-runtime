#!/usr/bin/env python3
"""Fail-closed Ed25519 ticket issuer, activated only by independent signed receipts.

No self-approved text, chat/issue comment, CLI boolean or naked cost URL can
create a ticket. The trusted owner/cost issuers are OUTSIDE this module/host.
Private keys must be injected by a separately approved secure signing service.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

import lenovo_inventory_api_bridge as bridge

FIELDS_COMMON = frozenset(("request_id", "idempotency_key", "expected_sha", "repository",
                           "workflow", "issued_at", "expires_at"))
OWNER_FIELDS = FIELDS_COMMON | {"kind", "authorized_user_id", "decision"}
COST_FIELDS = FIELDS_COMMON | {"kind", "cost_zero_certified", "cost_evidence_ref",
                               "evidence_sha256", "currency", "incremental_cost_max"}
MAX_TICKET_AGE = timedelta(minutes=10)


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise bridge.Blocked("attestation_time_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise bridge.Blocked("attestation_time_invalid") from None
    if parsed.tzinfo is None:
        raise bridge.Blocked("attestation_timezone_missing")
    return parsed.astimezone(timezone.utc)


def _verified_payload(document: dict, public_bytes: bytes, expected_fields: frozenset,
                      kind: str, now: datetime) -> dict:
    if (not isinstance(document, dict) or set(document) != {"payload", "signature"} or
            not isinstance(document["payload"], dict)):
        raise bridge.Blocked("attestation_envelope_invalid")
    payload = document["payload"]
    if set(payload) != expected_fields or payload["kind"] != kind:
        raise bridge.Blocked("attestation_fields_invalid")
    issued = _parse_time(payload["issued_at"])
    expires = _parse_time(payload["expires_at"])
    if not issued <= now < expires or not timedelta(0) < expires - issued <= MAX_TICKET_AGE:
        raise bridge.Blocked("attestation_not_current")
    try:
        signature = base64.b64decode(document["signature"], validate=True)
        if len(signature) != 64 or len(public_bytes) != 32:
            raise ValueError("signature size")
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, bridge.canonical(payload))
    except (ValueError, TypeError, InvalidSignature):
        raise bridge.Blocked("attestation_signature_invalid") from None
    return payload


def issue_ticket(owner_receipt: dict, cost_receipt: dict, *, owner_public: bytes,
                 cost_public: bytes, signing_key: Ed25519PrivateKey,
                 sha: str, now: datetime | None = None) -> dict:
    """Only the external authorized signing service may supply signing_key."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (not bridge.SHA_RE.fullmatch(sha) or owner_public == cost_public or
            not isinstance(signing_key, Ed25519PrivateKey)):
        raise bridge.Blocked("independent_authorities_required")
    owner = _verified_payload(owner_receipt, owner_public, OWNER_FIELDS,
                              "owner-authorization.v1", now)
    cost = _verified_payload(cost_receipt, cost_public, COST_FIELDS,
                             "independent-cost-zero.v1", now)
    for field in FIELDS_COMMON - {"issued_at", "expires_at"}:
        if owner[field] != cost[field]:
            raise bridge.Blocked("attestation_scope_disagreement")
    if (owner["authorized_user_id"] != bridge.OWNER_ID or
            owner["expected_sha"] != sha or
            owner["repository"] != f"{bridge.OWNER}/{bridge.REPO}" or
            owner["workflow"] != bridge.WORKFLOW or
            owner["decision"] != "authorize_one_readonly_inventory" or
            not isinstance(owner["request_id"], str) or
            not re.fullmatch(r"[a-zA-Z0-9_-]{8,80}", owner["request_id"]) or
            not isinstance(owner["idempotency_key"], str) or
            not bridge.HEX_RE.fullmatch(owner["idempotency_key"])):
        raise bridge.Blocked("attestation_scope_invalid")
    if (cost["cost_zero_certified"] is not True or
            cost["currency"] != "BRL" or
            type(cost["incremental_cost_max"]) not in (int, float) or
            cost["incremental_cost_max"] != 0 or
            not isinstance(cost["evidence_sha256"], str) or
            not bridge.HEX_RE.fullmatch(cost["evidence_sha256"])):
        raise bridge.Blocked("independent_cost_evidence_required")
    ref = cost["cost_evidence_ref"]
    if not isinstance(ref, str):
        raise bridge.Blocked("independent_cost_evidence_required")
    url = urlsplit(ref)
    if (url.scheme != "https" or url.netloc != "github.com" or
            not url.path.startswith(f"/{bridge.OWNER}/{bridge.REPO}/") or
            url.username or url.password or url.query or url.fragment):
        raise bridge.Blocked("independent_cost_evidence_required")
    expires = min(_parse_time(owner["expires_at"]),
                  _parse_time(cost["expires_at"]), now + MAX_TICKET_AGE)
    payload = {
        "request_id": owner["request_id"],
        "idempotency_key": owner["idempotency_key"],
        "authorized_user_id": bridge.OWNER_ID,
        "expected_sha": sha,
        "repository": f"{bridge.OWNER}/{bridge.REPO}",
        "workflow": bridge.WORKFLOW,
        "decision": "authorize_one_readonly_inventory",
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "cost_zero_certified": True,
        "cost_evidence_ref": ref,
    }
    signature = signing_key.sign(bridge.canonical(payload))
    return {"payload": payload, "signature": base64.b64encode(signature).decode("ascii")}
