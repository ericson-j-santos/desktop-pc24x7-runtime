"""Typed, fail-closed admission before scheduling the physical Desktop.

No request content is executed. Public GitHub read APIs only; no added token.
Admission is not the durable consumption claim.
"""
from __future__ import annotations
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

OWNER = "ericson-j-santos"
REPO = OWNER + "/desktop-pc24x7-runtime"
OWNER_ID = 60470500
SCOPE = "READ_ONLY_CAPACITY_NO_INSTALL"
CONSENT = "RISK2_AUDIT_ONLY_AT_MOST_ONCE"
TITLE = "Desktop capacity read-only request v1"
FIELDS = {"schema", "request_id", "expected_head_sha", "expected_rules_sha", "scope", "audit_claim"}
SHA = re.compile(r"[0-9a-f]{40}\Z")
REQUEST = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
MAX_AGE = 300

class AdmissionError(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise AdmissionError(reason)

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "DUPLICATE_FIELD")
        result[key] = value
    return result

def parse(body):
    require(isinstance(body, str) and 0 < len(body) <= 2048 and body.isascii(), "BODY_INVALID")
    try:
        data = json.loads(body, object_pairs_hook=pairs)
    except (ValueError, TypeError) as exc:
        raise AdmissionError("BODY_INVALID") from exc
    require(type(data) is dict and set(data) == FIELDS, "FIELDS_INVALID")
    require(type(data["schema"]) is int and data["schema"] == 1, "SCHEMA_INVALID")
    require(all(type(data[k]) is str for k in FIELDS - {"schema"}), "FIELD_TYPE_INVALID")
    require(bool(REQUEST.fullmatch(data["request_id"])), "REQUEST_ID_INVALID")
    require(bool(SHA.fullmatch(data["expected_head_sha"])) and bool(SHA.fullmatch(data["expected_rules_sha"])), "SHA_INVALID")
    require(data["scope"] == SCOPE and data["audit_claim"] == CONSENT, "SCOPE_INVALID")
    return data

def identity(user):
    return isinstance(user, dict) and user.get("login") == OWNER and type(user.get("id")) is int and user["id"] == OWNER_ID and user.get("type") == "User"

def timestamp(value):
    from datetime import datetime
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value), "TIME_INVALID")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError as exc:
        raise AdmissionError("TIME_INVALID") from exc

def validate_issue(issue, now):
    require(type(issue) is dict and "pull_request" not in issue and issue.get("state") == "open", "ISSUE_INVALID")
    require(type(issue.get("id")) is int and issue["id"] > 0 and type(issue.get("number")) is int and issue["number"] > 0, "ISSUE_ID_INVALID")
    require(identity(issue.get("user")), "AUTHOR_INVALID")
    require(issue.get("title") == TITLE and issue.get("updated_at") == issue.get("created_at"), "ISSUE_EDITED")
    age = now - timestamp(issue.get("created_at"))
    require(0 <= age <= MAX_AGE, "ISSUE_STALE")
    return parse(issue.get("body"))

def assess(event, env, get, now=time.time):
    require(env.get("GITHUB_EVENT_NAME") == "issues" and event.get("action") == "opened", "EVENT_INVALID")
    require(env.get("GITHUB_REPOSITORY") == REPO and env.get("GITHUB_REF") == "refs/heads/main", "REPOSITORY_OR_REF_INVALID")
    require(env.get("GITHUB_ACTOR") == OWNER and env.get("GITHUB_TRIGGERING_ACTOR") == OWNER and env.get("GITHUB_ACTOR_ID") == str(OWNER_ID), "ACTOR_INVALID")
    require(env.get("GITHUB_RUN_ATTEMPT") == "1" and re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", "")), "RERUN_INVALID")
    require(identity(event.get("sender")), "SENDER_INVALID")
    repo = event.get("repository", {})
    require(repo.get("full_name") == REPO and repo.get("default_branch") == "main" and repo.get("private") is False and identity(repo.get("owner")), "REPOSITORY_INVALID")
    issue = event.get("issue")
    data = validate_issue(issue, now())
    require(env.get("GITHUB_SHA") == data["expected_head_sha"], "EVENT_SHA_INVALID")
    fresh = get("/repos/" + REPO + "/issues/" + str(issue["number"]))
    validate_issue(fresh, now())
    for key in ("id", "number", "title", "body", "created_at", "updated_at"):
        require(fresh.get(key) == issue.get(key), "ISSUE_CHANGED")
    main = get("/repos/" + REPO + "/branches/main")
    rules = get("/repos/" + OWNER + "/chatgpt-operational-rules/branches/main")
    require(main.get("commit", {}).get("sha") == data["expected_head_sha"] and rules.get("commit", {}).get("sha") == data["expected_rules_sha"], "SOURCE_CHANGED")
    validate_issue(fresh, now())
    return {**data, "issue_id": str(issue["id"]), "issue_number": str(issue["number"]), "run_id": env["GITHUB_RUN_ID"], "issue_created_at": issue["created_at"]}

def api_get(path):
    require(path.startswith("/repos/" + OWNER + "/") and "?" not in path, "API_PATH_INVALID")
    request = urllib.request.Request("https://api.github.com" + path, headers={"Accept": "application/vnd.github+json", "User-Agent": "desktop-capacity-admission-v1", "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(request, timeout=10) as response:
        raw = response.read(262145)
        require(response.status == 200 and len(raw) <= 262144, "API_RESPONSE_INVALID")
    return json.loads(raw)

def main():
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        result = assess(event, os.environ, api_get)
        require(sys.argv[1:] in ([], ["--verify-only"]), "ARGUMENTS_INVALID")
        if sys.argv[1:] == ["--verify-only"]:
            require(result["request_id"] == os.environ.get("CAPACITY_REQUEST_ID") and result["expected_head_sha"] == os.environ.get("EXPECTED_HEAD") and result["expected_rules_sha"] == os.environ.get("EXPECTED_RULES"), "ADMITTED_REQUEST_CHANGED")
            print(json.dumps({"admitted": True, "request_id": result["request_id"]}))
            return 0
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            for key in ("request_id", "expected_head_sha", "expected_rules_sha", "issue_id", "issue_number", "run_id", "issue_created_at"):
                stream.write(key + "=" + result[key] + "\n")
            stream.write("admitted=true\n")
        print("CAPACITY_ISSUE_ADMISSION_OK_NO_PHYSICAL_CLAIM_YET")
        return 0
    except Exception as exc:
        print("CAPACITY_ADMISSION_BLOCKED:" + (str(exc) if isinstance(exc, AdmissionError) else type(exc).__name__))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
