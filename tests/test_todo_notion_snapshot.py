"""Regression gates for complete bounded Notion capture and safe API transport."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.error

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import todo_notion_snapshot as b
from notion_snapshot_fixture import (
    BLOCK_ONE, BLOCK_TWO, CHILD_PAGE, DATA_SOURCE_ID, DATABASE_ID,
    PAGE_ONE, PAGE_TWO, SyntheticNotionClient, rich, synthetic_snapshot,
)


def collect(client=None, **overrides):
    return b.collect_snapshot(client or SyntheticNotionClient(), **{
        "data_source_id": DATA_SOURCE_ID, "database_id": DATABASE_ID,
        "producer_sha": "a" * 40,
        "now": datetime(2026, 10, 19, 12, tzinfo=timezone.utc), **overrides,
    })


def rehash(snapshot):
    snapshot["content_sha256"] = hashlib.sha256(
        b.canonical_bytes(snapshot["content"])).hexdigest()
    return snapshot


def test_complete_capture_preserves_recursive_children_and_more_than_25_people():
    client = SyntheticNotionClient()
    result = collect(client)
    inventory = b.validate_snapshot(result)
    assert client.traversals == 2
    assert inventory["page_count"] == 3
    assert inventory["root_page_count"] == 2
    assert inventory["block_count"] == 5
    assert inventory["property_item_count"] == 61
    first = next(p for p in result["content"]["pages"] if p["page"]["id"] == PAGE_ONE)
    assert len(first["page"]["properties"]["Owner"]["people"]) == 25
    assert len(first["property_items"]["owner"]["items"]) == 26
    assert [item["title"]["plain_text"] for item in first["property_items"]["title"]["items"]] == [
        "Tarefa ", "1"]
    assert first["blocks"][0]["children"][0]["id"] == BLOCK_TWO
    assert any(p["page"]["id"] == CHILD_PAGE for p in result["content"]["pages"])
    assert result["consistency"]["transactional_snapshot"] is False
    assert result["scope"]["neon_exclusive_history"] == "excluded_not_recovered"


def test_shared_property_item_id_is_not_misclassified_as_duplicate():
    snapshot = synthetic_snapshot()
    items = snapshot["content"]["pages"][0]["property_items"]["title"]["items"]
    assert len(items) == 2 and {item["id"] for item in items} == {"title"}
    assert b.validate_snapshot(snapshot)["page_count"] == 3


def test_snapshot_is_deterministic_utf8_and_strictly_roundtrips():
    first = synthetic_snapshot()
    second = synthetic_snapshot()
    data = b.snapshot_bytes(first)
    assert data == b.snapshot_bytes(second)
    assert "ação".encode() in data
    assert b.strict_json(data) == first
    assert b.validate_snapshot(b.strict_json(data)) == b.validate_snapshot(first)


def test_query_capped_with_has_more_false_is_rejected():
    client = SyntheticNotionClient(batch_size=100)
    def hook(call, response):
        if call["method"] == "POST":
            response["request_status"] = {"type": "incomplete",
                                          "incomplete_reason": "query_result_limit_reached"}
            response["has_more"] = False
            response["next_cursor"] = None
        return response
    client.on_response = hook
    with pytest.raises(b.NotionBlocked, match="NOTION_QUERY_INCOMPLETE"):
        collect(client)


@pytest.mark.parametrize("fault,code", [
    ("missing_cursor", "NOTION_CURSOR_MISSING"),
    ("repeated_cursor", "NOTION_CURSOR_REPEATED"),
    ("unexpected_final_cursor", "NOTION_PAGINATION_INVALID"),
    ("nonboolean_more", "NOTION_PAGINATION_INVALID"),
])
def test_pagination_contract_failures_are_closed(fault, code):
    client = SyntheticNotionClient()
    def hook(call, response):
        if call["method"] == "POST":
            if fault == "missing_cursor":
                response.update(has_more=True, next_cursor=None)
            elif fault == "repeated_cursor":
                response.update(has_more=True, next_cursor="cursor-0")
            elif fault == "unexpected_final_cursor" and response["has_more"] is False:
                response["next_cursor"] = "unusable"
            elif fault == "nonboolean_more":
                response["has_more"] = "true"
        return response
    client.on_response = hook
    with pytest.raises(b.NotionBlocked, match=code):
        collect(client)


def test_empty_response_with_more_is_followed_to_completion():
    client = SyntheticNotionClient()
    injected = False
    original = client.request
    def request(method, path, *, query=None, payload=None):
        nonlocal injected
        if method == "POST" and not injected:
            injected = True
            return {"object": "list", "results": [], "has_more": True,
                    "next_cursor": "cursor-0", "request_status": {"type": "complete"}}
        return original(method, path, query=query, payload=payload)
    client.request = request
    assert b.validate_snapshot(collect(client))["root_page_count"] == 2


def test_duplicate_pages_are_rejected():
    client = SyntheticNotionClient()
    client.roots.append(PAGE_ONE)
    with pytest.raises(b.NotionBlocked, match="DUPLICATE_PAGE_ID"):
        collect(client)


def test_duplicate_blocks_are_rejected():
    client = SyntheticNotionClient()
    duplicate = deepcopy(client.blocks[PAGE_ONE][0])
    duplicate["parent"] = {"type": "page_id", "page_id": PAGE_TWO}
    client.blocks[PAGE_TWO].append(duplicate)
    with pytest.raises(b.NotionBlocked, match="DUPLICATE_BLOCK_ID"):
        collect(client)


def test_query_budget_blocks_silent_api_limit(monkeypatch):
    monkeypatch.setattr(b, "MAX_PAGES", 1)
    with pytest.raises(b.NotionBlocked, match="NOTION_QUERY_RESULT_LIMIT"):
        collect()


def test_pagination_budget_blocks_unbounded_reads(monkeypatch):
    monkeypatch.setattr(b, "MAX_PAGINATION", 1)
    with pytest.raises(b.NotionBlocked, match="NOTION_PAGINATION_LIMIT"):
        collect()


def test_expected_database_and_data_source_are_pinned():
    client = SyntheticNotionClient()
    client.schema["parent"]["database_id"] = PAGE_ONE
    with pytest.raises(b.NotionBlocked, match="DATABASE_MISMATCH"):
        collect(client)


def test_page_from_another_source_is_rejected():
    client = SyntheticNotionClient()
    client.pages[PAGE_TWO]["parent"]["data_source_id"] = DATABASE_ID
    with pytest.raises(b.NotionBlocked, match="PAGE_PARENT_MISMATCH"):
        collect(client)


def test_missing_returned_schema_property_is_rejected():
    client = SyntheticNotionClient()
    client.pages[PAGE_ONE]["properties"].pop("State")
    with pytest.raises(b.NotionBlocked, match="PAGE_SCHEMA_INCOMPLETE"):
        collect(client)


def test_unknown_schema_property_is_rejected():
    client = SyntheticNotionClient()
    client.schema["properties"]["State"]["type"] = "future_unimplemented_type"
    with pytest.raises(b.NotionBlocked, match="UNSUPPORTED_PROPERTY_TYPE"):
        collect(client)


def test_duplicate_people_references_are_rejected():
    client = SyntheticNotionClient()
    kind, values = client.property_values[(PAGE_ONE, "owner")]
    client.property_values[(PAGE_ONE, "owner")] = (kind, values + [deepcopy(values[0])])
    with pytest.raises(b.NotionBlocked, match="DUPLICATE_PROPERTY_TARGET"):
        collect(client)


@pytest.mark.parametrize("kind", ["child_database", "unsupported", "image", "future_block"])
def test_unsupported_or_binary_blocks_cannot_report_complete(kind):
    client = SyntheticNotionClient()
    original = client.blocks[PAGE_TWO][0]
    original.pop(original["type"])
    original["type"] = kind
    original[kind] = {}
    with pytest.raises(b.NotionBlocked, match="UNSUPPORTED_BLOCK_TYPE"):
        collect(client)


def test_expiring_binary_page_cover_is_rejected():
    client = SyntheticNotionClient()
    client.pages[PAGE_ONE]["cover"] = {
        "type": "file", "file": {"url": "https://example.invalid/secret-signed-url",
                                "expiry_time": "2026-10-19T13:00:00Z"}}
    with pytest.raises(b.NotionBlocked, match="BINARY_CONTENT_NOT_SUPPORTED") as error:
        collect(client)
    assert "secret-signed-url" not in str(error.value)


def test_external_synced_block_is_rejected():
    client = SyntheticNotionClient()
    block = client.blocks[PAGE_TWO][0]
    block.pop(block["type"])
    block.update(type="synced_block", synced_block={"synced_from": {"block_id": BLOCK_ONE}})
    with pytest.raises(b.NotionBlocked, match="EXTERNAL_SYNCED_BLOCK_NOT_SUPPORTED"):
        collect(client)


def test_every_property_cursor_is_completed_and_next_url_is_never_followed():
    client = SyntheticNotionClient()
    def hook(call, response):
        if "property_item" in response:
            response["property_item"]["next_url"] = "https://attacker.invalid/steal"
        return response
    client.on_response = hook
    result = collect(client)
    assert b.validate_snapshot(result)["property_item_count"] == 61
    assert not any("attacker.invalid" in call["path"] for call in client.calls)
    assert all("%253A" not in call["path"] for call in client.calls)


@pytest.mark.parametrize("change", ["schema", "block"])
def test_two_complete_passes_detect_changed_content_even_without_timestamp_change(change):
    client = SyntheticNotionClient()
    def hook(call, response):
        if client.traversals == 2:
            if change == "schema" and response.get("object") == "data_source":
                response["title"] = [rich("Alterado")]
            if change == "block" and call["path"] == f"/v1/blocks/{PAGE_TWO}/children":
                response["results"][0]["code"]["rich_text"] = [rich("modified")]
        return response
    client.on_response = hook
    with pytest.raises(b.NotionBlocked, match="NOTION_SOURCE_CHANGED_DURING_CAPTURE"):
        collect(client)


def test_child_page_payload_is_required_during_offline_validation():
    snapshot = synthetic_snapshot()
    snapshot["content"]["pages"] = [p for p in snapshot["content"]["pages"]
                                   if p["page"]["id"] != CHILD_PAGE]
    with pytest.raises(b.NotionBlocked, match="CHILD_PAGE_CONTENT_MISSING"):
        b.validate_snapshot(rehash(snapshot))


def test_nested_children_are_required_during_offline_validation():
    snapshot = synthetic_snapshot()
    snapshot["content"]["pages"][0]["blocks"][0]["children"] = []
    with pytest.raises(b.NotionBlocked, match="BLOCK_CHILDREN_INCOMPLETE"):
        b.validate_snapshot(rehash(snapshot))


def test_paginated_property_payload_is_required_during_offline_validation():
    snapshot = synthetic_snapshot()
    snapshot["content"]["pages"][0]["property_items"].pop("owner")
    with pytest.raises(b.NotionBlocked, match="PROPERTY_PAGINATION_MISSING"):
        b.validate_snapshot(rehash(snapshot))


def test_digest_detects_tampered_content():
    snapshot = synthetic_snapshot()
    snapshot["content"]["data_source"]["title"][0]["plain_text"] = "different"
    with pytest.raises(b.NotionBlocked, match="SNAPSHOT_CONTENT_DIGEST_MISMATCH"):
        b.validate_snapshot(snapshot)


def test_scope_cannot_be_relabelled_as_full_workspace_or_neon_recovery():
    snapshot = synthetic_snapshot()
    snapshot["scope"]["neon_exclusive_history"] = "recovered"
    with pytest.raises(b.NotionBlocked, match="SNAPSHOT_SCOPE_INVALID"):
        b.validate_snapshot(snapshot)


@pytest.mark.parametrize("data,code", [
    (b'{"same":1,"same":2}', "DUPLICATE_JSON_KEY"),
    (b'{"number":NaN}', "NONFINITE_JSON"),
    (b"[]", "JSON_OBJECT_REQUIRED"),
    (b"\xff", "JSON_INVALID"),
])
def test_strict_parser_refuses_ambiguous_or_invalid_json(data, code):
    with pytest.raises(b.NotionBlocked, match=code):
        b.strict_json(data)


@pytest.mark.parametrize("sha", ["main", "", "a" * 39, "A" * 40])
def test_full_producer_sha_required(sha):
    with pytest.raises(b.NotionBlocked, match="PRODUCER_SHA_REQUIRED"):
        collect(producer_sha=sha)


def test_relation_ids_are_preserved_with_explicit_external_boundary():
    client = SyntheticNotionClient()
    external = "60000000-0000-4000-8000-000000000001"
    client.schema["properties"]["Related"] = {
        "id": "rel", "name": "Related", "type": "relation",
        "relation": {"data_source_id": DATA_SOURCE_ID, "type": "single_property",
                     "single_property": {}}}
    for ident in (PAGE_ONE, PAGE_TWO):
        values = [{"id": PAGE_ONE}, {"id": PAGE_TWO}, {"id": external}]
        client.pages[ident]["properties"]["Related"] = {
            "id": "rel", "type": "relation", "relation": values[:1], "has_more": True}
        client.property_values[(ident, "rel")] = ("relation", values)
    snapshot = collect(client)
    inventory = b.validate_snapshot(snapshot)
    assert inventory["relation_count"] == 6
    assert inventory["external_relation_page_count"] == 1
    assert snapshot["scope"]["relation_target_contents_outside_scope"] == "references_only"


@pytest.mark.parametrize("terminal_type", ["number", "incomplete", "unsupported"])
def test_rollup_only_accepts_final_completed_calculation(terminal_type):
    client = SyntheticNotionClient()
    client.schema["properties"]["Score"] = {
        "id": "score", "name": "Score", "type": "rollup",
        "rollup": {"function": "sum", "relation_property_id": "rel",
                   "rollup_property_id": "number"}}
    for ident in (PAGE_ONE, PAGE_TWO):
        client.pages[ident]["properties"]["Score"] = {
            "id": "score", "type": "rollup", "rollup": {"type": "number", "number": 3,
                                                      "function": "sum"}}
        client.property_values[(ident, "score")] = (
            "rollup", [{"id": PAGE_ONE}, {"id": PAGE_TWO}])
    def hook(call, response):
        if call["path"].endswith("/properties/score"):
            for item in response["results"]:
                value = item.pop("rollup")
                item.update(type="relation", relation=value)
            kind = "incomplete" if response["has_more"] else terminal_type
            response["property_item"]["rollup"] = {
                "type": kind, "function": "sum", kind: 3 if kind == "number" else {}}
        return response
    client.on_response = hook
    if terminal_type == "number":
        snapshot = collect(client)
        assert snapshot["content"]["pages"][0]["property_items"]["score"]["rollup"]["number"] == 3
    else:
        with pytest.raises(b.NotionBlocked, match="ROLLUP_NOT_COMPLETE"):
            collect(client)


def test_formula_is_read_through_its_authoritative_property_endpoint():
    client = SyntheticNotionClient()
    client.schema["properties"]["Calc"] = {
        "id": "calc", "name": "Calc", "type": "formula", "formula": {"expression": "1+2"}}
    for ident in (PAGE_ONE, PAGE_TWO):
        formula = {"type": "number", "number": 3}
        client.pages[ident]["properties"]["Calc"] = {
            "id": "calc", "type": "formula", "formula": formula}
        client.property_values[(ident, "calc")] = ("formula", [formula])
    def hook(call, response):
        if call["path"].endswith("/properties/calc"):
            return response["results"][0]
        return response
    client.on_response = hook
    snapshot = collect(client)
    item = snapshot["content"]["pages"][0]["property_items"]["calc"]["items"][0]
    assert item["formula"]["number"] == 3
    assert len([call for call in client.calls if call["path"].endswith("/properties/calc")]) == 4


def test_malformed_response_does_not_escape_as_unsanitized_runtime_exception():
    client = SyntheticNotionClient()
    client.schema["properties"]["State"]["type"] = {"private-content": "must-not-echo"}
    with pytest.raises(b.NotionBlocked, match="NOTION_RESPONSE_OR_SNAPSHOT_INVALID") as raised:
        collect(client)
    assert "private-content" not in str(raised.value)


class Reply:
    status = 200
    def __init__(self, url, data=b"{}"):
        self.url, self.data = url, data
    def geturl(self):
        return self.url
    def read(self, limit):
        return self.data[:limit]
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class Opener:
    def __init__(self, replies=None):
        self.requests = []
        self.replies = list(replies or [])
    def open(self, request, timeout):
        self.requests.append(request)
        if self.replies:
            result = self.replies.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        return Reply(request.full_url)


def test_api_auth_is_sent_only_to_fixed_notion_host(monkeypatch):
    opener = Opener()
    monkeypatch.setattr(b.urllib.request, "build_opener", lambda *args: opener)
    api = b.NotionClient("synthetic-test-token-only")
    assert api.request("GET", f"/v1/data_sources/{DATA_SOURCE_ID}") == {}
    req = opener.requests[0]
    assert req.full_url == f"https://api.notion.com/v1/data_sources/{DATA_SOURCE_ID}"
    assert req.get_header("Authorization") == "Bearer synthetic-test-token-only"
    assert req.get_header("Notion-version") == "2026-03-11"


@pytest.mark.parametrize("method,path,payload", [
    ("GET", "https://attacker.invalid/v1/pages/example", None),
    ("GET", "//attacker.invalid/anything", None),
    ("GET", "/v1/users/me", None),
    ("PATCH", f"/v1/pages/{PAGE_ONE}", {"in_trash": True}),
    ("POST", f"/v1/pages/{PAGE_ONE}", {}),
])
def test_unsupported_api_destinations_and_mutations_are_blocked(monkeypatch, method, path, payload):
    opener = Opener()
    monkeypatch.setattr(b.urllib.request, "build_opener", lambda *args: opener)
    api = b.NotionClient("synthetic-test-token-only")
    with pytest.raises(b.NotionBlocked, match="UNTRUSTED_NOTION_ROUTE"):
        api.request(method, path, payload=payload)
    assert opener.requests == []


def test_redirect_is_not_followed_and_errors_do_not_echo_secret(monkeypatch):
    url = f"https://api.notion.com/v1/data_sources/{DATA_SOURCE_ID}"
    error = urllib.error.HTTPError(url, 302, "secret-body-token", {"Location": "https://evil.invalid"},
                                   io.BytesIO(b"secret-body-token"))
    opener = Opener([error])
    monkeypatch.setattr(b.urllib.request, "build_opener", lambda *args: opener)
    api = b.NotionClient("synthetic-test-token-only")
    with pytest.raises(b.NotionBlocked, match="NOTION_REDIRECT_BLOCKED") as raised:
        api.request("GET", f"/v1/data_sources/{DATA_SOURCE_ID}")
    assert len(opener.requests) == 1 and "secret-body-token" not in str(raised.value)


def test_rate_limit_is_retried_with_retry_after_without_echoing_body(monkeypatch):
    url = f"https://api.notion.com/v1/data_sources/{DATA_SOURCE_ID}"
    error = urllib.error.HTTPError(url, 429, "secret-message", {"Retry-After": "0"},
                                   io.BytesIO(b'{"object":"error","message":"private content"}'))
    opener = Opener([error, Reply(url)])
    waits = []
    monkeypatch.setattr(b.urllib.request, "build_opener", lambda *args: opener)
    monkeypatch.setattr(b.time, "sleep", waits.append)
    api = b.NotionClient("synthetic-test-token-only")
    assert api.request("GET", f"/v1/data_sources/{DATA_SOURCE_ID}") == {}
    assert len(opener.requests) == 2 and waits
    assert all(req.full_url == url for req in opener.requests)


def test_restricted_api_does_not_retry_past_access_control(monkeypatch):
    url = f"https://api.notion.com/v1/data_sources/{DATA_SOURCE_ID}"
    error = urllib.error.HTTPError(
        url, 429, "blocked", {"Retry-After": "0"},
        io.BytesIO(b'{"additional_data":{"rate_limit_reason":"public_api_request_blocked"}}'))
    opener = Opener([error])
    monkeypatch.setattr(b.urllib.request, "build_opener", lambda *args: opener)
    api = b.NotionClient("synthetic-test-token-only")
    with pytest.raises(b.NotionBlocked, match="NOTION_ACCESS_BLOCKED"):
        api.request("GET", f"/v1/data_sources/{DATA_SOURCE_ID}")
    assert len(opener.requests) == 1


def test_excessive_retry_after_fails_without_retrying_early(monkeypatch):
    url = f"https://api.notion.com/v1/data_sources/{DATA_SOURCE_ID}"
    error = urllib.error.HTTPError(url, 529, "busy", {"Retry-After": "3600"}, io.BytesIO(b"{}"))
    opener = Opener([error])
    monkeypatch.setattr(b.urllib.request, "build_opener", lambda *args: opener)
    api = b.NotionClient("synthetic-test-token-only")
    with pytest.raises(b.NotionBlocked, match="NOTION_RETRY_WINDOW_EXCEEDS_BUDGET"):
        api.request("GET", f"/v1/data_sources/{DATA_SOURCE_ID}")
    assert len(opener.requests) == 1
