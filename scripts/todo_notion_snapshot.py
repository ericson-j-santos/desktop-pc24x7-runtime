"""Bounded read-only preservation of one explicitly configured Notion data source.

The archive contains API-visible active pages, complete paginated properties and
recursive supported blocks. It does not contain permissions, comments, revision
history, linked external content or the history exclusive to the retired Neon bus.
Two equal complete traversals detect observed changes; they are not a transaction.
All errors are stable codes. Never print API bodies, tokens or page contents.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import functools
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Protocol

API_VERSION = "2026-03-11"
SCHEMA_VERSION = "todo-notion-snapshot-v1"
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 9999
MAX_BLOCKS = 100000
MAX_DEPTH = 32
MAX_PAGINATION = 100
MAX_PROPERTY_ITEMS = 10000
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SHA64 = re.compile(r"[0-9a-f]{64}\Z")
PAGED_TYPES = {"title", "rich_text", "people", "relation", "rollup"}
HYDRATED_TYPES = PAGED_TYPES | {"formula"}
PROPERTY_TYPES = PAGED_TYPES | {
    "number", "select", "multi_select", "status", "date", "files", "checkbox",
    "url", "email", "phone_number", "formula", "created_by", "created_time",
    "last_edited_by", "last_edited_time", "unique_id", "verification", "button",
    "place",
}
BLOCK_TYPES = {
    "paragraph", "heading_1", "heading_2", "heading_3", "heading_4",
    "bulleted_list_item", "numbered_list_item", "quote", "to_do", "toggle",
    "template", "synced_block", "child_page", "equation", "code", "callout",
    "divider", "breadcrumb", "table_of_contents", "tab", "column_list", "column",
    "link_to_page", "table", "table_row", "meeting_notes", "embed", "bookmark",
    "link_preview",
}
SCOPE = {
    "selection": "all_api_visible_active_pages_in_configured_data_source_and_child_pages",
    "page_properties": "all_returned_properties_with_complete_property_item_pagination",
    "page_content": "recursive_supported_blocks",
    "binary_files": "rejected",
    "external_link_contents": "references_only",
    "relation_target_contents_outside_scope": "references_only",
    "comments": "excluded",
    "permissions": "excluded",
    "revision_history": "excluded",
    "trashed_and_archived_pages": "excluded",
    "neon_exclusive_history": "excluded_not_recovered",
}
CONSISTENCY = {
    "method": "two_equal_complete_traversals",
    "transactional_snapshot": False,
}


class NotionBlocked(RuntimeError):
    """A non-sensitive machine-readable failure code."""


def _safe_validation(function):
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except NotionBlocked:
            raise
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
            raise NotionBlocked("NOTION_RESPONSE_OR_SNAPSHOT_INVALID") from None
    return guarded


def require(ok: Any, code: str) -> None:
    if not ok:
        raise NotionBlocked(code)


def _id(value: Any) -> str:
    require(isinstance(value, str) and bool(re.fullmatch(
        r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})",
        value)), "NOTION_ID_INVALID")
    return str(uuid.UUID(value))


def _property_id(value: Any) -> str:
    require(isinstance(value, str) and 0 < len(value) <= 256, "PROPERTY_ID_INVALID")
    try:
        decoded = urllib.parse.unquote(value, errors="strict")
    except (ValueError, UnicodeError):
        raise NotionBlocked("PROPERTY_ID_INVALID") from None
    require(decoded not in {".", ".."} and
            all(ord(c) >= 32 and ord(c) != 127 for c in decoded), "PROPERTY_ID_INVALID")
    # Notion returns already URL-encoded IDs. Normalize once, never double encode.
    return urllib.parse.quote(decoded, safe="")


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def strict_json(data: bytes) -> dict:
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_SNAPSHOT_BYTES,
            "JSON_SIZE_INVALID")
    try:
        result = json.loads(
            data.decode("utf-8"), object_pairs_hook=_strict_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(NotionBlocked("NONFINITE_JSON")),
        )
    except (ValueError, UnicodeError, RecursionError):
        raise NotionBlocked("JSON_INVALID") from None
    require(isinstance(result, dict), "JSON_OBJECT_REQUIRED")
    return result


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise NotionBlocked("JSON_INVALID") from None


def _copy_object(value: Any) -> dict:
    require(isinstance(value, dict), "NOTION_OBJECT_INVALID")
    result = strict_json(canonical_bytes(value))
    result.pop("request_id", None)
    return result


def _guard_values(value: Any, depth: int = 0) -> None:
    require(depth <= 128, "JSON_DEPTH_LIMIT")
    if isinstance(value, dict):
        kind = value.get("type")
        if isinstance(kind, str):
            require(kind != "unsupported", "UNSUPPORTED_NOTION_VALUE")
            require(not (kind in {"file", "file_upload", "external", "custom_emoji"}
                         and isinstance(value.get(kind), dict)),
                    "BINARY_CONTENT_NOT_SUPPORTED")
            if kind == "files":
                files = value.get("files")
                require(not isinstance(files, list) or not files,
                        "BINARY_CONTENT_NOT_SUPPORTED")
        for child in value.values():
            _guard_values(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _guard_values(child, depth + 1)


class Client(Protocol):
    def request(self, method: str, path: str, *, query: dict | None = None,
                payload: dict | None = None) -> dict: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class NotionClient:
    """Bearer credentials go only to fixed HTTPS API routes; redirects are denied."""

    def __init__(self, token: str):
        require(isinstance(token, str) and 16 <= len(token) <= 4096 and
                all(33 <= ord(c) <= 126 for c in token), "NOTION_TOKEN_MISSING")
        self._token = token
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect)
        self._next_request = 0.0
        self._calls = 0

    def request(self, method: str, path: str, *, query: dict | None = None,
                payload: dict | None = None) -> dict:
        ident = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
        get_route = (rf"/v1/(?:data_sources/{ident}|pages/{ident}"
                     rf"(?:/properties/[A-Za-z0-9._~%+-]+)?|blocks/{ident}/children)")
        query_route = rf"/v1/data_sources/{ident}/query"
        require(isinstance(path, str) and (
            method == "GET" and bool(re.fullmatch(get_route, path)) and payload is None
            or method == "POST" and bool(re.fullmatch(query_route, path))
            and isinstance(payload, dict)
        ), "UNTRUSTED_NOTION_ROUTE")
        require(query is None or isinstance(query, dict) and
                set(query) <= {"page_size", "start_cursor"}, "NOTION_QUERY_INVALID")
        if payload is not None:
            require(set(payload) <= {"page_size", "start_cursor", "sorts", "is_archived"},
                    "NOTION_QUERY_INVALID")
        url = "https://api.notion.com" + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        body = None if payload is None else canonical_bytes(payload)
        for attempt in range(5):
            self._calls += 1
            require(self._calls <= 20000, "NOTION_REQUEST_LIMIT")
            delay = self._next_request - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self._next_request = time.monotonic() + 0.35
            req = urllib.request.Request(url, data=body, method=method, headers={
                "Authorization": "Bearer " + self._token,
                "Notion-Version": API_VERSION,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "todo-notion-preservation/1",
            })
            retry_after = None
            try:
                with self._opener.open(req, timeout=25) as response:
                    require(response.geturl() == url, "NOTION_REDIRECT_BLOCKED")
                    require(response.status == 200, "NOTION_RESPONSE_STATUS_INVALID")
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                require(0 < len(raw) <= MAX_RESPONSE_BYTES, "NOTION_RESPONSE_SIZE_INVALID")
                return strict_json(raw)
            except urllib.error.HTTPError as error:
                status = error.code
                if 300 <= status < 400:
                    raise NotionBlocked("NOTION_REDIRECT_BLOCKED") from None
                if status not in {429, 500, 502, 503, 504, 529}:
                    raise NotionBlocked("NOTION_API_ACCESS_OR_REQUEST_FAILED") from None
                retry_after = error.headers.get("Retry-After") if error.headers else None
                if status == 429:
                    try:
                        detail = strict_json(error.read(65537))
                    except NotionBlocked:
                        detail = {}
                    additional = detail.get("additional_data")
                    require(not isinstance(additional, dict) or additional.get("rate_limit_reason")
                            != "public_api_request_blocked", "NOTION_ACCESS_BLOCKED")
            except (OSError, TimeoutError):
                raise NotionBlocked("NOTION_API_UNAVAILABLE") from None
            require(attempt < 4, "NOTION_RETRY_LIMIT")
            if retry_after is not None:
                require(bool(re.fullmatch(r"[0-9]{1,6}", retry_after)),
                        "NOTION_RETRY_AFTER_INVALID")
                wait = int(retry_after)
                require(wait <= 60, "NOTION_RETRY_WINDOW_EXCEEDS_BUDGET")
            else:
                wait = 2 ** attempt
            # Every allowed POST is a read-only data source query and can be retried.
            time.sleep(wait + 0.05 * (attempt + 1))
        raise NotionBlocked("NOTION_RETRY_LIMIT")


def _pagination(response: Any, cursors: set[str]) -> str | None:
    require(isinstance(response, dict) and response.get("object") == "list" and
            isinstance(response.get("results"), list) and
            type(response.get("has_more")) is bool, "NOTION_PAGINATION_INVALID")
    status = response.get("request_status")
    require(status is None or isinstance(status, dict) and status.get("type") == "complete",
            "NOTION_QUERY_INCOMPLETE")
    require(len(response["results"]) <= 100, "NOTION_PAGE_SIZE_INVALID")
    cursor = response.get("next_cursor")
    if not response["has_more"]:
        require(cursor is None, "NOTION_PAGINATION_INVALID")
        return None
    require(isinstance(cursor, str) and 0 < len(cursor) <= 2048,
            "NOTION_CURSOR_MISSING")
    require(cursor not in cursors, "NOTION_CURSOR_REPEATED")
    cursors.add(cursor)
    return cursor


def _list_all(client: Client, method: str, path: str,
              base: dict | None = None) -> list[dict]:
    results: list[dict] = []
    cursors: set[str] = set()
    cursor = None
    for _ in range(MAX_PAGINATION):
        params = {"page_size": 100, **(base or {})}
        if cursor is not None:
            params["start_cursor"] = cursor
        response = client.request(method, path, **(
            {"payload": params} if method == "POST" else {"query": params}))
        cursor = _pagination(response, cursors)
        results.extend(response["results"])
        require(len(results) <= MAX_PAGES, "NOTION_QUERY_RESULT_LIMIT")
        if cursor is None:
            return results
    raise NotionBlocked("NOTION_PAGINATION_LIMIT")


def _parent(value: dict) -> tuple[str, str]:
    parent = value.get("parent")
    require(isinstance(parent, dict) and parent.get("type") in
            {"data_source_id", "database_id", "page_id", "block_id"}, "NOTION_PARENT_INVALID")
    kind = parent["type"]
    return kind, _id(parent.get(kind))


def _active(value: dict) -> None:
    require(value.get("in_trash") is False and value.get("is_archived", False) is False,
            "NOTION_INACTIVE_OBJECT")


def _data_source(value: dict, source_id: str, database_id: str) -> dict[str, dict]:
    require(value.get("object") == "data_source" and _id(value.get("id")) == source_id,
            "DATA_SOURCE_MISMATCH")
    require(_parent(value) == ("database_id", database_id), "DATABASE_MISMATCH")
    _active(value)
    properties = value.get("properties")
    require(isinstance(properties, dict) and 0 < len(properties) <= 100,
            "DATA_SOURCE_SCHEMA_INVALID")
    identifiers: set[str] = set()
    for prop in properties.values():
        require(isinstance(prop, dict) and prop.get("type") in PROPERTY_TYPES,
                "UNSUPPORTED_PROPERTY_TYPE")
        ident = _property_id(prop.get("id"))
        require(ident not in identifiers, "DUPLICATE_PROPERTY_ID")
        identifiers.add(ident)
    _guard_values(value)
    return properties


def _read_property(client: Client, page_id: str, prop: dict) -> dict:
    kind = prop["type"]
    ident = _property_id(prop["id"])
    results: list[dict] = []
    cursors: set[str] = set()
    cursor = None
    terminal: dict = {}
    for _ in range(MAX_PAGINATION):
        query: dict = {"page_size": 100}
        if cursor is not None:
            query["start_cursor"] = cursor
        response = client.request("GET", f"/v1/pages/{page_id}/properties/{ident}", query=query)
        if kind == "formula":
            require(isinstance(response, dict) and response.get("object") == "property_item"
                    and response.get("type") == kind and _property_id(response.get("id")) == ident
                    and isinstance(response.get("formula"), dict), "PROPERTY_ITEM_INVALID")
            _guard_values(response)
            return {"type": kind, "items": [_copy_object(response)]}
        cursor = _pagination(response, cursors)
        meta = response.get("property_item")
        require(isinstance(meta, dict) and _property_id(meta.get("id")) == ident
                and meta.get("type") == kind, "PROPERTY_ITEM_METADATA_INVALID")
        for item in response["results"]:
            require(isinstance(item, dict) and item.get("object") == "property_item"
                    and _property_id(item.get("id")) == ident
                    and item.get("type") in PROPERTY_TYPES
                    and item["type"] in item, "PROPERTY_ITEM_INVALID")
            require(kind == "rollup" or item["type"] == kind, "PROPERTY_ITEM_TYPE_MISMATCH")
            results.append(_copy_object(item))
        require(len(results) <= MAX_PROPERTY_ITEMS, "PROPERTY_ITEM_LIMIT")
        terminal = meta
        if cursor is None:
            result = {"type": kind, "items": results}
            if kind == "rollup":
                rollup = terminal.get("rollup")
                require(isinstance(rollup, dict) and rollup.get("type") in
                        {"number", "date", "array"}, "ROLLUP_NOT_COMPLETE")
                result["rollup"] = _copy_object(rollup)
            _guard_values(result)
            return result
    raise NotionBlocked("PROPERTY_PAGINATION_LIMIT")


def _page_properties(page: dict, schema: dict | None, items: dict) -> None:
    properties = page.get("properties")
    require(isinstance(properties, dict) and 0 < len(properties) <= 100,
            "PAGE_PROPERTIES_INVALID")
    if schema is not None:
        require(set(properties) == set(schema), "PAGE_SCHEMA_INCOMPLETE")
    seen: set[str] = set()
    required_items: set[str] = set()
    for name, prop in properties.items():
        require(isinstance(prop, dict) and prop.get("type") in PROPERTY_TYPES
                and prop["type"] in prop, "PAGE_PROPERTY_INVALID")
        ident = _property_id(prop.get("id"))
        require(ident not in seen, "DUPLICATE_PROPERTY_ID")
        seen.add(ident)
        kind = prop["type"]
        if schema is not None:
            require(ident == _property_id(schema[name]["id"]) and
                    kind == schema[name]["type"], "PAGE_SCHEMA_MISMATCH")
        if kind in HYDRATED_TYPES:
            required_items.add(ident)
            hydrated = items.get(ident)
            require(isinstance(hydrated, dict) and hydrated.get("type") == kind and
                    isinstance(hydrated.get("items"), list), "PROPERTY_PAGINATION_MISSING")
            require(len(hydrated["items"]) <= MAX_PROPERTY_ITEMS, "PROPERTY_ITEM_LIMIT")
            require(kind != "formula" or len(hydrated["items"]) == 1, "PROPERTY_ITEM_INVALID")
            related: set[str] = set()
            for item in hydrated["items"]:
                require(isinstance(item, dict) and item.get("object") == "property_item"
                        and _property_id(item.get("id")) == ident
                        and item.get("type") in PROPERTY_TYPES
                        and item["type"] in item, "PROPERTY_ITEM_INVALID")
                require(kind == "rollup" or item["type"] == kind, "PROPERTY_ITEM_TYPE_MISMATCH")
                if kind in {"relation", "people"}:
                    target = _id(item[kind].get("id")) if isinstance(item[kind], dict) else ""
                    require(target and target not in related, "DUPLICATE_PROPERTY_TARGET")
                    related.add(target)
            if kind == "rollup":
                rollup = hydrated.get("rollup")
                require(isinstance(rollup, dict) and rollup.get("type") in
                        {"number", "date", "array"}, "ROLLUP_NOT_COMPLETE")
    require(set(items) == required_items, "PROPERTY_ITEMS_SCOPE_MISMATCH")
    _guard_values(page)
    _guard_values(items)


def _block_header(block: dict, parent: tuple[str, str]) -> str:
    require(block.get("object") == "block" and block.get("type") in BLOCK_TYPES,
            "UNSUPPORTED_BLOCK_TYPE")
    ident = _id(block.get("id"))
    require(_parent(block) == parent, "BLOCK_PARENT_MISMATCH")
    _active(block)
    require(type(block.get("has_children")) is bool, "BLOCK_CHILDREN_FLAG_INVALID")
    require(isinstance(block.get(block["type"]), dict), "BLOCK_CONTENT_INVALID")
    if block["type"] == "synced_block":
        require(block["synced_block"].get("synced_from") is None,
                "EXTERNAL_SYNCED_BLOCK_NOT_SUPPORTED")
    _guard_values({key: value for key, value in block.items() if key != "children"})
    return ident


def _collect_once(client: Client, source_id: str, database_id: str) -> dict:
    source = _copy_object(client.request("GET", f"/v1/data_sources/{source_id}"))
    schema = _data_source(source, source_id, database_id)
    roots = _list_all(client, "POST", f"/v1/data_sources/{source_id}/query", {
        "sorts": [{"timestamp": "created_time", "direction": "ascending"}],
        "is_archived": False,
    })
    require(0 < len(roots) <= MAX_PAGES, "NOTION_SOURCE_EMPTY_OR_LIMITED")
    queue = deque((page, ("data_source_id", source_id), 0) for page in roots)
    pages: list[dict] = []
    page_ids: set[str] = set()
    block_ids: set[str] = set()

    def blocks(parent: tuple[str, str], depth: int) -> list[dict]:
        require(depth <= MAX_DEPTH, "NOTION_DEPTH_LIMIT")
        found = _list_all(client, "GET", f"/v1/blocks/{parent[1]}/children")
        result = []
        for raw in found:
            block = _copy_object(raw)
            require("children" not in block, "UNEXPECTED_INLINE_CHILDREN")
            ident = _block_header(block, parent)
            require(ident not in block_ids, "DUPLICATE_BLOCK_ID")
            block_ids.add(ident)
            require(len(block_ids) <= MAX_BLOCKS, "NOTION_BLOCK_LIMIT")
            if block["type"] == "child_page":
                child = _copy_object(client.request("GET", f"/v1/pages/{ident}"))
                queue.append((child, parent, depth + 1))
                block["children"] = []
            else:
                block["children"] = blocks(("block_id", ident), depth + 1) \
                    if block["has_children"] else []
            result.append(block)
        return result

    while queue:
        raw, parent, depth = queue.popleft()
        require(depth <= MAX_DEPTH, "NOTION_DEPTH_LIMIT")
        page = _copy_object(raw)
        require(page.get("object") == "page" and _parent(page) == parent,
                "PAGE_PARENT_MISMATCH")
        ident = _id(page.get("id"))
        require(ident not in page_ids, "DUPLICATE_PAGE_ID")
        page_ids.add(ident)
        require(len(page_ids) <= MAX_PAGES, "NOTION_PAGE_LIMIT")
        _active(page)
        properties = page.get("properties")
        require(isinstance(properties, dict), "PAGE_PROPERTIES_INVALID")
        property_items = {}
        for prop in properties.values():
            require(isinstance(prop, dict) and prop.get("type") in PROPERTY_TYPES,
                    "UNSUPPORTED_PROPERTY_TYPE")
            if prop["type"] in HYDRATED_TYPES:
                property_items[_property_id(prop.get("id"))] = _read_property(client, ident, prop)
        _page_properties(page, schema if parent[0] == "data_source_id" else None, property_items)
        pages.append({"page": page, "property_items": property_items,
                      "blocks": blocks(("page_id", ident), depth)})
    pages.sort(key=lambda item: _id(item["page"]["id"]))
    content = {"data_source": source, "pages": pages}
    require(len(canonical_bytes(content)) <= MAX_SNAPSHOT_BYTES - 65536,
            "NOTION_SNAPSHOT_SIZE_LIMIT")
    return content


@_safe_validation
def collect_snapshot(client: Client, *, data_source_id: str, database_id: str,
                     producer_sha: str, now: datetime | None = None) -> dict:
    source_id, database_id = _id(data_source_id), _id(database_id)
    require(isinstance(producer_sha, str) and bool(SHA40.fullmatch(producer_sha)),
            "PRODUCER_SHA_REQUIRED")
    captured = now if now is not None else datetime.now(timezone.utc)
    require(isinstance(captured, datetime) and captured.tzinfo is not None,
            "CAPTURE_TIME_INVALID")
    first = _collect_once(client, source_id, database_id)
    second = _collect_once(client, source_id, database_id)
    raw = canonical_bytes(first)
    require(raw == canonical_bytes(second), "NOTION_SOURCE_CHANGED_DURING_CAPTURE")
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "producer_sha": producer_sha,
        "captured_at": captured.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {"provider": "notion", "api_version": API_VERSION,
                   "data_source_id": source_id, "database_id": database_id},
        "scope": dict(SCOPE), "consistency": dict(CONSISTENCY),
        "content": first, "content_sha256": hashlib.sha256(raw).hexdigest(),
    }
    validate_snapshot(snapshot)
    return snapshot


@_safe_validation
def validate_snapshot(snapshot: dict) -> dict:
    require(isinstance(snapshot, dict) and set(snapshot) == {
        "schema_version", "producer_sha", "captured_at", "source", "scope",
        "consistency", "content", "content_sha256"}, "SNAPSHOT_SHAPE_INVALID")
    require(snapshot["schema_version"] == SCHEMA_VERSION, "SNAPSHOT_VERSION_INVALID")
    producer = snapshot["producer_sha"]
    require(isinstance(producer, str) and bool(SHA40.fullmatch(producer)),
            "PRODUCER_SHA_REQUIRED")
    try:
        stamp = datetime.fromisoformat(snapshot["captured_at"].replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        raise NotionBlocked("CAPTURE_TIME_INVALID") from None
    require(stamp.tzinfo is not None, "CAPTURE_TIME_INVALID")
    require(snapshot["scope"] == SCOPE and snapshot["consistency"] == CONSISTENCY,
            "SNAPSHOT_SCOPE_INVALID")
    source = snapshot["source"]
    require(isinstance(source, dict) and set(source) ==
            {"provider", "api_version", "data_source_id", "database_id"} and
            source["provider"] == "notion" and source["api_version"] == API_VERSION,
            "SNAPSHOT_SOURCE_INVALID")
    source_id, database_id = _id(source["data_source_id"]), _id(source["database_id"])
    content = snapshot["content"]
    require(isinstance(content, dict) and set(content) == {"data_source", "pages"},
            "SNAPSHOT_CONTENT_INVALID")
    schema = _data_source(content["data_source"], source_id, database_id)
    pages = content["pages"]
    require(isinstance(pages, list) and 0 < len(pages) <= MAX_PAGES,
            "SNAPSHOT_PAGES_INVALID")
    page_ids: set[str] = set()
    page_parents: dict[str, tuple[str, str]] = {}
    block_ids: set[str] = set()
    block_owners: dict[str, str] = {}
    child_links: dict[str, tuple[str, str]] = {}
    relations: set[str] = set()
    counts = {"page_count": len(pages), "root_page_count": 0, "block_count": 0,
              "property_item_count": 0, "relation_count": 0}

    def check_blocks(children: Any, parent: tuple[str, str], depth: int, owner: str) -> None:
        require(isinstance(children, list) and depth <= MAX_DEPTH, "SNAPSHOT_BLOCKS_INVALID")
        for block in children:
            require(isinstance(block, dict), "SNAPSHOT_BLOCKS_INVALID")
            ident = _block_header(block, parent)
            require(ident not in block_ids, "DUPLICATE_BLOCK_ID")
            block_ids.add(ident)
            block_owners[ident] = owner
            require(len(block_ids) <= MAX_BLOCKS, "NOTION_BLOCK_LIMIT")
            nested = block.get("children")
            require(isinstance(nested, list), "BLOCK_CHILDREN_MISSING")
            if block["type"] == "child_page":
                require(not nested, "CHILD_PAGE_CONTENT_AMBIGUOUS")
                child_links[ident] = parent
            else:
                require(block["has_children"] or not nested, "BLOCK_CHILDREN_FLAG_MISMATCH")
                require(not block["has_children"] or bool(nested), "BLOCK_CHILDREN_INCOMPLETE")
                check_blocks(nested, ("block_id", ident), depth + 1, owner)

    for wrapper in pages:
        require(isinstance(wrapper, dict) and set(wrapper) ==
                {"page", "property_items", "blocks"}, "SNAPSHOT_PAGE_INVALID")
        page = wrapper["page"]
        require(isinstance(page, dict) and page.get("object") == "page", "SNAPSHOT_PAGE_INVALID")
        ident = _id(page.get("id"))
        require(ident not in page_ids, "DUPLICATE_PAGE_ID")
        page_ids.add(ident)
        parent = _parent(page)
        page_parents[ident] = parent
        _active(page)
        if parent[0] == "data_source_id":
            require(parent[1] == source_id, "PAGE_SOURCE_MISMATCH")
            counts["root_page_count"] += 1
        else:
            require(parent[0] in {"page_id", "block_id"}, "PAGE_PARENT_MISMATCH")
        items = wrapper["property_items"]
        require(isinstance(items, dict), "PROPERTY_ITEMS_SCOPE_MISMATCH")
        _page_properties(page, schema if parent[0] == "data_source_id" else None, items)
        for hydrated in items.values():
            counts["property_item_count"] += len(hydrated["items"])
            if hydrated["type"] == "relation":
                counts["relation_count"] += len(hydrated["items"])
                relations.update(_id(item["relation"]["id"]) for item in hydrated["items"])
        check_blocks(wrapper["blocks"], ("page_id", ident), 0, ident)
    require(counts["root_page_count"] > 0, "ROOT_PAGES_MISSING")
    for ident, parent in page_parents.items():
        if parent[0] != "data_source_id":
            require(child_links.get(ident) == parent, "CHILD_PAGE_PARENT_MISMATCH")
    nested_pages = {ident for ident, parent in page_parents.items()
                    if parent[0] != "data_source_id"}
    require(set(child_links) == nested_pages, "CHILD_PAGE_CONTENT_MISSING")
    require(block_ids & page_ids == set(child_links), "NOTION_OBJECT_ID_COLLISION")
    for ident in nested_pages:
        visited: set[str] = set()
        current = ident
        for _ in range(MAX_DEPTH + 1):
            require(current not in visited, "CHILD_PAGE_CYCLE")
            visited.add(current)
            parent = page_parents.get(current)
            require(parent is not None, "CHILD_PAGE_PARENT_MISSING")
            if parent[0] == "data_source_id":
                break
            current = parent[1] if parent[0] == "page_id" else block_owners.get(parent[1], "")
        else:
            raise NotionBlocked("NOTION_DEPTH_LIMIT")
    counts["block_count"] = len(block_ids)
    counts["external_relation_page_count"] = len(relations - page_ids)
    digest = snapshot["content_sha256"]
    require(isinstance(digest, str) and bool(SHA64.fullmatch(digest)) and
            hashlib.sha256(canonical_bytes(content)).hexdigest() == digest,
            "SNAPSHOT_CONTENT_DIGEST_MISMATCH")
    require(len(canonical_bytes(snapshot)) <= MAX_SNAPSHOT_BYTES, "NOTION_SNAPSHOT_SIZE_LIMIT")
    return {**counts, "content_sha256": digest, "producer_sha": producer,
            "schema_version": SCHEMA_VERSION}


def snapshot_bytes(snapshot: dict) -> bytes:
    validate_snapshot(snapshot)
    return canonical_bytes(snapshot)
