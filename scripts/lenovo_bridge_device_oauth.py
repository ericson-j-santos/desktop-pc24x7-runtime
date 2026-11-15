#!/usr/bin/env python3
"""OAuth device flow for a *separately approved* GitHub App; no token storage.

The existing Lenovo bridge remains the sole holder of dispatch/CI/cost gates.
This CLI never registers apps, creates signatures, changes host or runs CI.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from urllib import error, parse, request

import lenovo_inventory_api_bridge as bridge

LOGIN_ORIGIN = "https://github.com"
APP_PERMISSIONS = {"metadata": "read", "contents": "read", "actions": "write", "variables": "write"}


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise bridge.Blocked("oauth_redirect_forbidden")


def post_form(endpoint: str, fields: dict[str, str]) -> dict:
    """Two hardcoded OAuth endpoints. Never emit body, headers or token."""
    if endpoint not in ("/login/device/code", "/login/oauth/access_token"):
        raise bridge.Blocked("oauth_endpoint_not_allowlisted")
    req = request.Request(
        LOGIN_ORIGIN + endpoint, method="POST",
        data=parse.urlencode(fields).encode("ascii"),
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
                 "User-Agent": "reqsys-lenovo-device-oauth/1"},
    )
    try:
        with request.build_opener(NoRedirect()).open(req, timeout=15) as response:
            if response.status != 200 or response.url != LOGIN_ORIGIN + endpoint:
                raise bridge.Blocked("oauth_response_untrusted")
            raw = response.read(16385)
        if len(raw) > 16384:
            raise bridge.Blocked("oauth_response_too_large")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise bridge.Blocked("oauth_response_invalid")
        return payload
    except (error.HTTPError, error.URLError, TimeoutError, ValueError, UnicodeError):
        raise bridge.Blocked("oauth_service_unavailable") from None


def start_device_flow(client_id: str, send=post_form) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{8,90}", client_id):
        raise bridge.Blocked("github_app_client_id_invalid")
    response = send("/login/device/code", {"client_id": client_id, "scope": "offline_access"})
    if (not isinstance(response, dict) or
        not isinstance(response.get("device_code"), str) or
        not 16 <= len(response["device_code"]) <= 300 or
        not isinstance(response.get("user_code"), str) or
        not re.fullmatch(r"[A-Z0-9-]{6,30}", response["user_code"]) or
        response.get("verification_uri") != LOGIN_ORIGIN + "/login/device" or
        type(response.get("expires_in")) is not int or
        not 60 <= response["expires_in"] <= 900 or
        type(response.get("interval")) is not int or
        not 5 <= response["interval"] <= 60):
        raise bridge.Blocked("oauth_device_challenge_invalid")
    return response


def poll_token(client_id: str, challenge: dict, send=post_form,
               clock=time.monotonic, pause=time.sleep) -> str:
    deadline = clock() + challenge["expires_in"]
    interval = challenge["interval"]
    while clock() + interval < deadline:
        pause(interval)
        result = send("/login/oauth/access_token", {
            "client_id": client_id,
            "device_code": challenge["device_code"],
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        })
        if not isinstance(result, dict):
            raise bridge.Blocked("oauth_token_response_invalid")
        if "error" in result:
            if result["error"] == "authorization_pending":
                continue
            if result["error"] == "slow_down":
                interval = min(interval + 5, 60)
                continue
            raise bridge.Blocked("oauth_authorization_denied_or_expired")
        token = result.get("access_token")
        if (not isinstance(token, str) or
            not token.startswith("ghu_") or len(token) < 20 or
            result.get("token_type", "").lower() != "bearer" or
            type(result.get("expires_in")) is not int or
            result["expires_in"] < 60):
            raise bridge.Blocked("github_app_user_token_required")
        # Refresh token, if received, is deliberately not persisted or printed.
        return token
    raise bridge.Blocked("oauth_device_authorization_expired")


def verify_restricted_installation(api: bridge.Api, app_id: int) -> None:
    """Identity + precisely one selected repository + no excess app permissions."""
    if type(app_id) is not int or app_id <= 0:
        raise bridge.Blocked("github_app_id_invalid")
    identity = api.call("GET", "/user")
    if identity.get("login") != bridge.OWNER or identity.get("id") != bridge.OWNER_ID:
        raise bridge.Blocked("github_app_oauth_owner_mismatch")
    entries = api.call("GET", "/user/installations?per_page=100")
    installations = entries.get("installations")
    if (not isinstance(installations, list) or
        entries.get("total_count") != len(installations)):
        raise bridge.Blocked("github_app_installation_listing_incomplete")
    matching = [x for x in installations if
                x.get("app_id") == app_id and
                x.get("account", {}).get("login") == bridge.OWNER]
    if len(matching) != 1:
        raise bridge.Blocked("github_app_installation_not_unique")
    inst = matching[0]
    if (type(inst.get("id")) is not int or inst["id"] <= 0 or
            inst.get("repository_selection") != "selected" or
            inst.get("permissions") != APP_PERMISSIONS or
            inst.get("suspended_at") is not None):
        raise bridge.Blocked("github_app_installation_scope_rejected")
    repos = api.call("GET", f"/user/installations/{inst['id']}/repositories?per_page=100")
    items = repos.get("repositories")
    if (not isinstance(items, list) or repos.get("total_count") != 1 or len(items) != 1 or
            items[0].get("full_name") != f"{bridge.OWNER}/{bridge.REPO}" or
            items[0].get("private") is not False):
        raise bridge.Blocked("github_app_repository_scope_rejected")


def invoke_bridge(action: str, sha: str, token: str, *, ticket: str | None = None,
                  database: str | None = None, run_id: int | None = None) -> int:
    args = [action, "--sha", sha]
    if action == "dispatch":
        if not ticket or not database:
            raise bridge.Blocked("signed_ticket_and_durable_database_required")
        args += ["--ticket", ticket, "--database", database]
    elif action == "status":
        if type(run_id) is not int or run_id < 1:
            raise bridge.Blocked("run_id_required")
        args += ["--run-id", str(run_id)]
    previous = os.environ.get("REQSYS_GITHUB_APP_USER_TOKEN")
    try:
        os.environ["REQSYS_GITHUB_APP_USER_TOKEN"] = token
        return bridge.main(args)
    finally:
        if previous is None:
            os.environ.pop("REQSYS_GITHUB_APP_USER_TOKEN", None)
        else:
            os.environ["REQSYS_GITHUB_APP_USER_TOKEN"] = previous


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="GitHub App OAuth temporario sem Docker")
    parser.add_argument("action", choices=("preflight", "status", "dispatch"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--app-id", type=int, required=True)
    parser.add_argument("--ticket")
    parser.add_argument("--database")
    parser.add_argument("--run-id", type=int)
    args = parser.parse_args(argv)
    try:
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise bridge.Blocked("interactive_owner_consent_required")
        if not bridge.SHA_RE.fullmatch(args.sha):
            raise bridge.Blocked("sha_invalid")
        if args.action == "dispatch" and (not args.ticket or not args.database):
            raise bridge.Blocked("signed_ticket_and_durable_database_required")
        if args.action == "status" and (not args.run_id or args.run_id < 1):
            raise bridge.Blocked("run_id_required")
        challenge = start_device_flow(args.client_id)
        # Only the short user-facing code may appear in an authenticated, local TTY.
        print("Abra https://github.com/login/device e informe: " + challenge["user_code"],
              file=sys.stderr, flush=True)
        token = poll_token(args.client_id, challenge)
        verify_restricted_installation(bridge.Api(token), args.app_id)
        return invoke_bridge(args.action, args.sha, token, ticket=args.ticket,
                             database=args.database, run_id=args.run_id)
    except (bridge.Blocked, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, bridge.Blocked) else "dependency_unavailable"
        print(json.dumps({"result": "BLOCKED", "reason": reason}, sort_keys=True))
        return 3


if __name__ == "__main__":
    sys.exit(main())
