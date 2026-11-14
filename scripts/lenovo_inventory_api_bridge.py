#!/usr/bin/env python3
"""Ponte opt-in para o inventario Lenovo. Nunca faz upgrade nem cria autorizacao.

Exige ticket Ed25519 de um autorizador externo autenticado, token de usuario da
GitHub App e uma base SQLite duravel de escritor unico. Sem ticket, so preflight.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path
from urllib import error, parse, request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

OWNER = "ericson-j-santos"
REPO = "desktop-pc24x7-runtime"
OWNER_ID = 60470500
WORKFLOW = "lenovo-installed-inventory-readonly.yml"
VARIABLE = "REQSYS_PC24X7_COST_ZERO_CERTIFIED_SHA"
CONFIRMATION = "READ_ONLY_LENOVO_INVENTORY"
BASE = f"/repos/{OWNER}/{REPO}"
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")


class Blocked(RuntimeError):
    """Recusa identificada sem expor tokens/segredos."""


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def verify_ticket(document: dict, public_key: bytes, sha: str, now: datetime | None = None) -> dict:
    """Somente um autorizador externo com chave privada pode gerar o ticket."""
    now = now or datetime.now(timezone.utc)
    if set(document) != {"payload", "signature"} or not isinstance(document["payload"], dict):
        raise Blocked("approval_envelope_invalid")
    payload = document["payload"]
    required = {"request_id", "idempotency_key", "authorized_user_id", "expected_sha",
                "repository", "workflow", "decision", "issued_at", "expires_at",
                "cost_zero_certified", "cost_evidence_ref"}
    if set(payload) != required:
        raise Blocked("approval_fields_invalid")
    if (type(payload["authorized_user_id"]) is not int or
            payload["authorized_user_id"] != OWNER_ID or
            payload["expected_sha"] != sha or payload["repository"] != f"{OWNER}/{REPO}" or
            payload["workflow"] != WORKFLOW or
            payload["decision"] != "authorize_one_readonly_inventory" or
            payload["cost_zero_certified"] is not True or
            not isinstance(payload["cost_evidence_ref"], str) or
            not payload["cost_evidence_ref"].startswith("https://github.com/") or
            not isinstance(payload["request_id"], str) or
            not re.fullmatch(r"[a-zA-Z0-9_-]{8,80}", payload["request_id"]) or
            not isinstance(payload["idempotency_key"], str) or
            not HEX_RE.fullmatch(payload["idempotency_key"])):
        raise Blocked("approval_contract_rejected")
    try:
        issued = datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
        if (issued.tzinfo is None or expires.tzinfo is None or
                issued > now or now >= expires or expires - issued > timedelta(minutes=10)):
            raise Blocked("approval_expired_or_future")
        signature = base64.b64decode(document["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical(payload))
    except (ValueError, TypeError, KeyError, InvalidSignature) as exc:
        raise Blocked("approval_signature_or_time_invalid") from exc
    return payload


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("api_redirect_forbidden")


class Api:
    """API oficial com host fixo, sem redirecionamentos arbitrarios."""

    def __init__(self, token: str):
        if not token.startswith("ghu_") or len(token) < 20:
            raise Blocked("github_app_user_token_required")
        self.token = token

    def call(self, method: str, path: str, data: dict | None = None) -> dict:
        if not path.startswith("/") or ".." in path or "//" in path:
            raise Blocked("api_path_invalid")
        body = canonical(data) if data is not None else None
        req = request.Request(
            "https://api.github.com" + path, data=body, method=method,
            headers={"Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2026-03-10",
                     "Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json", "User-Agent": "reqsys-lenovo-bridge/1"})
        try:
            with request.build_opener(NoRedirect()).open(req, timeout=15) as response:
                raw = response.read(2_000_000)
                if response.status not in (200, 201, 204) or response.url.split("/", 3)[2] != "api.github.com":
                    raise Blocked("api_response_untrusted")
                return json.loads(raw) if raw else {}
        except (error.HTTPError, error.URLError, TimeoutError, ValueError) as exc:
            # Nao propagar corpo de erro, headers ou token.
            raise Blocked("github_api_unavailable_or_denied") from None


def assert_owner_and_main(api: Api, sha: str) -> None:
    user = api.call("GET", "/user")
    if user.get("login") != OWNER or user.get("id") != OWNER_ID:
        raise Blocked("owner_oauth_identity_mismatch")
    repo = api.call("GET", BASE)
    if repo.get("full_name") != f"{OWNER}/{REPO}" or repo.get("private") is not False:
        raise Blocked("repository_not_public_or_mismatch")
    branch = api.call("GET", BASE + "/branches/main")
    if branch.get("commit", {}).get("sha") != sha:
        raise Blocked("main_sha_moved")


def assert_ci(api: Api, sha: str) -> int:
    query = parse.urlencode({"branch": "main", "head_sha": sha, "event": "push",
                             "status": "completed", "per_page": 100})
    runs = api.call("GET", BASE + "/actions/workflows/ci.yml/runs?" + query)
    if runs.get("total_count") != 1 or len(runs.get("workflow_runs", [])) != 1:
        raise Blocked("ci_run_not_unique")
    run = runs["workflow_runs"][0]
    if (run.get("head_sha") != sha or run.get("head_branch") != "main" or
            run.get("event") != "push" or run.get("status") != "completed" or
            run.get("conclusion") != "success" or run.get("run_attempt") != 1):
        raise Blocked("ci_not_approved")
    jobs = api.call("GET", BASE + f"/actions/runs/{run['id']}/jobs?per_page=100")
    if jobs.get("total_count") != len(jobs.get("jobs", [])):
        raise Blocked("ci_jobs_incomplete")
    for name, label in (("Python compile and tests", "windows-latest"),
                        ("Portable Linux compile and tests", "ubuntu-latest")):
        matches = [j for j in jobs["jobs"] if j.get("name") == name]
        if len(matches) != 1 or matches[0].get("status") != "completed" or matches[0].get("conclusion") != "success" or label not in matches[0].get("labels", []) or not any(
                s.get("name") == "Unit and negative-control tests" and
                s.get("conclusion") == "success" and s.get("status") == "completed"
                for s in matches[0].get("steps", [])):
            raise Blocked("ci_required_job_not_approved")
    return run["id"]


def reserve(connection: sqlite3.Connection, key: str, sha: str, request_id: str) -> dict | None:
    """Reserva antes de qualquer POST. Replay incompleto nao causa novo dispatch."""
    connection.execute("BEGIN IMMEDIATE")
    row = connection.execute("SELECT sha, request_id, state, run_id FROM dispatches WHERE idempotency_key=?", (key,)).fetchone()
    if row:
        connection.commit()
        if row[0] != sha or row[1] != request_id:
            raise Blocked("idempotency_key_reused_for_different_request")
        if row[2] == "dispatched":
            return {"result": "REPLAY_SAME_RUN", "run_id": row[3], "sha": sha}
        raise Blocked("reserved_or_unknown_outcome_needs_reconciliation")
    connection.execute("INSERT INTO dispatches VALUES(?,?,?,?,?)",
                       (key, sha, request_id, "reserved", None))
    connection.commit()
    return None


@contextmanager
def database(path: Path):
    """Fecha a conexao no Windows e POSIX mesmo quando a operacao falha."""
    if not path.is_absolute() or not path.parent.is_dir() or path.is_symlink():
        raise Blocked("durable_state_directory_invalid")
    conn = sqlite3.connect(path, timeout=1, isolation_level=None)
    try:
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("CREATE TABLE IF NOT EXISTS dispatches (idempotency_key TEXT PRIMARY KEY, sha TEXT NOT NULL, request_id TEXT NOT NULL, state TEXT NOT NULL, run_id INTEGER)")
        yield conn
    finally:
        conn.close()


def execute(api: Api, db: sqlite3.Connection, ticket: dict, sha: str) -> dict:
    """Apenas um disparo. Em resultado HTTP incerto, reserva impede replay cego."""
    assert_owner_and_main(api, sha)
    ci_run_id = assert_ci(api, sha)
    replay = reserve(db, ticket["idempotency_key"], sha, ticket["request_id"])
    if replay:
        return replay
    # Mesmo depois da reserva, revalidar main antes de alterar variavel.
    assert_owner_and_main(api, sha)
    varpath = BASE + "/actions/variables/" + VARIABLE
    previous = api.call("GET", varpath)
    if previous.get("name") != VARIABLE:
        raise Blocked("certification_variable_missing")
    api.call("PATCH", varpath, {"name": VARIABLE, "value": sha})
    readback = api.call("GET", varpath)
    if readback.get("name") != VARIABLE or readback.get("value") != sha:
        raise Blocked("certification_readback_failed")
    assert_owner_and_main(api, sha)
    dispatch = api.call("POST", BASE + f"/actions/workflows/{WORKFLOW}/dispatches",
                        {"ref": "main", "return_run_details": True,
                         "inputs": {"expected_source_sha": sha, "confirmation": CONFIRMATION}})
    run_id = dispatch.get("workflow_run_id")
    if type(run_id) is not int or run_id <= 0 or dispatch.get("html_url") != (
            f"https://github.com/{OWNER}/{REPO}/actions/runs/{run_id}"):
        raise Blocked("dispatch_result_ambiguous_no_retry")
    db.execute("UPDATE dispatches SET state='dispatched', run_id=? WHERE idempotency_key=? AND state='reserved'",
               (run_id, ticket["idempotency_key"]))
    return {"result": "DISPATCH_CREATED_NOT_YET_VALIDATED", "run_id": run_id,
            "sha": sha, "ci_run_id": ci_run_id, "request_id": ticket["request_id"]}


def readback(api: Api, run_id: int, sha: str) -> dict:
    """Nao confundir status success com recibo fisico autenticado."""
    run = api.call("GET", BASE + f"/actions/runs/{run_id}")
    if (run.get("id") != run_id or run.get("head_sha") != sha or
            run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main" or
            run.get("actor", {}).get("login") != OWNER):
        raise Blocked("run_identity_mismatch")
    jobs = api.call("GET", BASE + f"/actions/runs/{run_id}/jobs?per_page=100")
    if jobs.get("total_count") != len(jobs.get("jobs", [])):
        raise Blocked("run_jobs_incomplete")
    inv = [x for x in jobs["jobs"] if x.get("name") == "inventory"]
    if len(inv) != 1:
        raise Blocked("inventory_job_not_unique")
    job = inv[0]
    return {"result": "RUN_METADATA_ONLY_PHYSICAL_RECEIPT_PENDING",
            "run_id": run_id, "sha": sha,
            "status": run.get("status"), "conclusion": run.get("conclusion"),
            "job_status": job.get("status"), "job_conclusion": job.get("conclusion"),
            "runner_name": job.get("runner_name"), "runner_id": job.get("runner_id"),
            "physical_receipt_proven": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ponte Lenovo governada, sem upgrade")
    parser.add_argument("action", choices=("preflight", "dispatch", "status"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--ticket")
    parser.add_argument("--database")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args(argv)
    if not SHA_RE.fullmatch(args.sha):
        print(json.dumps({"result": "BLOCKED", "reason": "sha_invalid"}))
        return 3
    try:
        api = Api(os.environ.get("REQSYS_GITHUB_APP_USER_TOKEN", ""))
        if args.action == "preflight":
            assert_owner_and_main(api, args.sha)
            ci = assert_ci(api, args.sha)
            output = {"result": "GITHUB_READONLY_PREFLIGHT_OK_NOT_AUTHORIZED", "sha": args.sha, "ci_run_id": ci}
        elif args.action == "status":
            if args.run_id is None or args.run_id <= 0:
                raise Blocked("run_id_required")
            output = readback(api, args.run_id, args.sha)
        else:
            if not args.ticket or not args.database:
                raise Blocked("signed_ticket_and_durable_database_required")
            public = bytes.fromhex(os.environ.get("REQSYS_BRIDGE_APPROVER_PUBLIC_KEY", ""))
            ticket = verify_ticket(json.loads(Path(args.ticket).read_text(encoding="utf-8")), public, args.sha)
            with database(Path(args.database)) as db:
                output = execute(api, db, ticket, args.sha)
        print(json.dumps(output, sort_keys=True))
        return 0
    except (Blocked, OSError, ValueError, sqlite3.Error) as exc:
        reason = str(exc) if isinstance(exc, Blocked) else "dependency_unavailable"
        print(json.dumps({"result": "BLOCKED", "reason": reason}, sort_keys=True))
        return 3


if __name__ == "__main__":
    sys.exit(main())
