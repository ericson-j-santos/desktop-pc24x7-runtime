"""Canário read-only do bridge TODO Global → Worker Pool no PC24x7.

O código de admissão permanece no Engineering Worker Pool. Este adaptador
apenas comprova a prontidão do host/endpoint DEV via sessão e Command Gateway.
Não publica eventos, não enfileira tarefas, não lê valores para logs e não
executa comandos externos.
"""
from __future__ import annotations

import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any, Mapping

HOST = "DESKTOP-PDQK954"
NEEDED = (
    "PORTFOLIO_NOTION_TOKEN_FILE",
    "PORTFOLIO_GITHUB_TOKEN_FILE",
    "PORTFOLIO_WORKER_TOKEN_FILE",
    "PORTFOLIO_WORKER_URL",
    "PORTFOLIO_TODO_PAGE_ID",
    "PORTFOLIO_TODO_DATA_SOURCE_ID",
)
TOKEN_FILES = NEEDED[:3]
SHA_RE = re.compile(r"^[a-f0-9]{40}$")


def blocked(reason: str, **evidence: Any) -> dict[str, Any]:
    return {"state": "blocked", "reason": reason, "dispatched": False, **evidence}


def probe(env: Mapping[str, str], *, hostname: str, bridge: Any) -> dict[str, Any]:
    """Read-only, com transporte injetável para testes positivos/negativos."""
    if hostname.casefold() != HOST.casefold():
        return blocked("host_not_authorized")
    if env.get("PORTFOLIO_ENV") != "dev":
        return blocked("dev_profile_required")
    absent = sorted(k for k in NEEDED if not str(env.get(k) or "").strip())
    if absent:
        return blocked("config_reference_missing", missing=absent)
    sha = str(env.get("WORKER_POOL_SHA") or "").strip().lower()
    if not SHA_RE.fullmatch(sha):
        return blocked("worker_pool_sha_invalid")
    for key in TOKEN_FILES:
        # Apenas existência de arquivo. Nunca registrar o caminho nem o conteúdo.
        try:
            if not Path(env[key]).is_file():
                return blocked("protected_token_file_missing", reference=key)
        except (OSError, ValueError):
            return blocked("protected_token_file_unavailable", reference=key)
    try:
        url = bridge._allowed_worker_url(env["PORTFOLIO_WORKER_URL"])
        token = bridge._token_from_file(env["PORTFOLIO_WORKER_TOKEN_FILE"])
        transport = bridge.JsonTransport()
        http_status, health = transport.request("worker", "GET", url + "/health", token)
        if http_status != 200 or not isinstance(health, dict):
            return blocked("worker_health_unavailable")
        if (
            health.get("status") != "healthy"
            or health.get("auth_configured") is not True
            or health.get("expected_rules_sha_configured") is not True
        ):
            return blocked("worker_not_ready")
        source = bridge.run_page(
            page_id=env["PORTFOLIO_TODO_PAGE_ID"],
            data_source_id=env["PORTFOLIO_TODO_DATA_SOURCE_ID"],
            transport=transport,
            notion_token=bridge._token_from_file(env["PORTFOLIO_NOTION_TOKEN_FILE"]),
            github_token=bridge._token_from_file(env["PORTFOLIO_GITHUB_TOKEN_FILE"]),
            execute=False,
            environment="dev",
        )
        if source.get("state") != "ready_for_dispatch" or source.get("dispatched") is not False:
            return blocked("source_dry_run_not_verified")
        lane_status, lanes = transport.request("worker", "GET", url + "/v1/repositories", token)
        if lane_status != 200 or not isinstance(lanes, list):
            return blocked("worker_lanes_unavailable")
        selected = [
            row for row in lanes
            if isinstance(row, dict) and row.get("repository") == source.get("repository")
        ]
        if len(selected) != 1 or selected[0].get("enabled") is not True or selected[0].get("max_in_flight") != 1:
            return blocked("worker_lane_not_admitted")
    except Exception:
        # Não imprimir URLs internas, token, path ou corpo de resposta de provedor.
        return blocked("live_read_only_preflight_failed")
    return {
        "state": "read_only_preflight_passed",
        "dispatched": False,
        "repository": source["repository"],
        "issue_number": source["issue_number"],
        "base_sha": source["base_sha"],
        "worker_pool_sha": sha,
        "host_verified": True,
        "worker_healthy": True,
        "lane_max_in_flight": 1,
    }


def load_bridge(env: Mapping[str, str]):
    workspace = str(env.get("GITHUB_WORKSPACE") or "").strip()
    worker_root = str(env.get("WORKER_POOL_ROOT") or "").strip()
    if not workspace or not worker_root:
        raise ValueError("worker_checkout_reference_missing")
    root = Path(workspace).resolve()
    worker = Path(worker_root).resolve()
    if worker != root / "external" / "engineering-worker-pool":
        raise ValueError("worker_checkout_path_invalid")
    if not (worker / "app" / "portfolio_bridge.py").is_file():
        raise ValueError("worker_checkout_missing")
    sys.path.insert(0, str(worker))
    from app import portfolio_bridge  # type: ignore[import-not-found]
    return portfolio_bridge


def main() -> int:
    env = os.environ
    if str(env.get("COMPUTERNAME") or socket.gethostname()).casefold() != HOST.casefold():
        result = blocked("host_not_authorized")
    else:
        try:
            facade = load_bridge(env)
        except (OSError, ValueError, ImportError):
            result = blocked("worker_checkout_unavailable")
        else:
            result = probe(env, hostname=str(env.get("COMPUTERNAME") or socket.gethostname()), bridge=facade)
    result["correlation_id"] = str(env.get("CORRELATION_ID") or "")[:128]
    result["runtime_head_sha"] = str(env.get("SESSION_SOURCE_SHA") or "")[:40]
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["state"] == "read_only_preflight_passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
