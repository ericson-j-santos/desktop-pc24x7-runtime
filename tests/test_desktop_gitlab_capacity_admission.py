"""Hermetic admission tests: no network, no host pickup."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("admission", Path(__file__).resolve().parents[1] / "scripts/desktop_gitlab_capacity_admission.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
USER = {"id": m.OWNER_ID, "login": m.OWNER, "type": "User"}
HEAD, RULES = "a" * 40, "b" * 40
BODY = {"schema": 1, "request_id": "01234567-89ab-4def-8123-456789abcdef", "expected_head_sha": HEAD, "expected_rules_sha": RULES, "scope": m.SCOPE, "audit_claim": m.CONSENT}
ISSUE = {"id": 100, "number": 12, "title": m.TITLE, "body": json.dumps(BODY), "state": "open", "user": USER, "created_at": "2026-10-30T15:00:00Z", "updated_at": "2026-10-30T15:00:00Z"}
EVENT = {"action": "opened", "sender": USER, "issue": ISSUE, "repository": {"full_name": m.REPO, "default_branch": "main", "private": False, "owner": USER}}
ENV = {"GITHUB_EVENT_NAME": "issues", "GITHUB_REPOSITORY": m.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_ACTOR": m.OWNER, "GITHUB_TRIGGERING_ACTOR": m.OWNER, "GITHUB_ACTOR_ID": str(m.OWNER_ID), "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "123456789", "GITHUB_SHA": HEAD}
NOW = m.timestamp(ISSUE["created_at"]) + 1

class AdmissionTests(unittest.TestCase):
    def run_case(self, event=None, env=None, live=None, now=None, head=HEAD, rules=RULES):
        def get(path):
            if "/issues/" in path:
                return copy.deepcopy(ISSUE if live is None else live)
            return {"commit": {"sha": rules if "operational-rules" in path else head}}
        return m.assess(copy.deepcopy(EVENT if event is None else event), dict(ENV if env is None else env), get, lambda: NOW if now is None else now)

    def test_positive(self):
        result = self.run_case()
        self.assertEqual(result["request_id"], BODY["request_id"])
        self.assertEqual(result["issue_id"], "100")

    def test_all_environment_guards(self):
        for key, value in {"GITHUB_EVENT_NAME": "issue_comment", "GITHUB_REPOSITORY": "other/repo", "GITHUB_REF": "refs/heads/dev", "GITHUB_ACTOR": "attacker", "GITHUB_TRIGGERING_ACTOR": "attacker", "GITHUB_ACTOR_ID": "1", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_RUN_ID": "1\nmalicious=true", "GITHUB_SHA": RULES}.items():
            with self.subTest(key=key), self.assertRaises(m.AdmissionError):
                self.run_case(env={**ENV, key: value})

    def test_event_actor_and_repo_guards(self):
        variants = []
        for key, value in {"action": "edited", "sender": {**USER, "id": 1}}.items():
            variants.append({**EVENT, key: value})
        for key, value in {"private": True, "default_branch": "other", "owner": {**USER, "id": 1}}.items():
            variants.append({**EVENT, "repository": {**EVENT["repository"], key: value}})
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(m.AdmissionError):
                self.run_case(event=variant)

    def test_issue_guards(self):
        for key, value in {"id": True, "number": -1, "state": "closed", "title": "other", "user": {**USER, "login": "other"}, "updated_at": "2026-10-30T15:00:01Z", "pull_request": {}}.items():
            with self.subTest(key=key), self.assertRaises(m.AdmissionError):
                self.run_case(event={**EVENT, "issue": {**ISSUE, key: value}})

    def test_live_edit_and_sha_drift(self):
        for kwargs in ({"live": {**ISSUE, "body": ISSUE["body"] + " "}}, {"head": RULES}, {"rules": HEAD}, {"now": NOW + 300}, {"now": NOW - 2}):
            with self.subTest(kwargs=kwargs), self.assertRaises(m.AdmissionError):
                self.run_case(**kwargs)

    def test_parser_rejects_extra_duplicate_wrong_types_and_injection(self):
        invalid = [
            json.dumps({**BODY, "extra": "x"}),
            json.dumps(BODY)[:-1] + ', "scope": "' + m.SCOPE + '"}',
            json.dumps({**BODY, "schema": True}),
            json.dumps({**BODY, "request_id": "x; shutdown"}),
            json.dumps({**BODY, "expected_head_sha": HEAD.upper()}),
            json.dumps({**BODY, "scope": "INSTALL"}),
            json.dumps({**BODY, "audit_claim": "NO"}),
            json.dumps({**BODY, "expected_rules_sha": []}),
            "x" * 2049, "é", "[]", "null",
        ]
        for body in invalid:
            with self.subTest(body=body), self.assertRaises(m.AdmissionError):
                m.parse(body)

    def test_freshness_rechecked_after_io(self):
        ticks = iter([NOW, NOW, NOW + 301])
        def get(path):
            return copy.deepcopy(ISSUE) if "/issues/" in path else {"commit": {"sha": RULES if "operational-rules" in path else HEAD}}
        with self.assertRaises(m.AdmissionError):
            m.assess(copy.deepcopy(EVENT), ENV, get, lambda: next(ticks))

    def test_api_error_fails_closed(self):
        def unavailable(path):
            raise OSError("transport unavailable")
        with self.assertRaises(OSError):
            m.assess(copy.deepcopy(EVENT), ENV, unavailable, lambda: NOW)

if __name__ == "__main__":
    unittest.main()
