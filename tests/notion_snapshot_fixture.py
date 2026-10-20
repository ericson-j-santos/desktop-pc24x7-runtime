"""Synthetic, offline-only fixtures for the Notion preservation pipeline.

Every ID and payload in this module is fabricated. No user data or credential is
used. The fake client models query, property and recursive block pagination.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import todo_notion_snapshot as snapshot_module

DATABASE_ID = "10000000-0000-4000-8000-000000000001"
DATA_SOURCE_ID = "20000000-0000-4000-8000-000000000001"
PAGE_ONE = "30000000-0000-4000-8000-000000000001"
PAGE_TWO = "30000000-0000-4000-8000-000000000002"
CHILD_PAGE = "30000000-0000-4000-8000-000000000003"
BLOCK_ONE = "40000000-0000-4000-8000-000000000001"
BLOCK_TWO = "40000000-0000-4000-8000-000000000002"
BLOCK_THREE = "40000000-0000-4000-8000-000000000003"
BLOCK_FOUR = "40000000-0000-4000-8000-000000000004"
STAMP = "2026-10-19T12:00:00.000Z"


def rich(text):
    return {"type": "text", "text": {"content": text, "link": None},
            "plain_text": text, "href": None,
            "annotations": {"bold": False, "italic": False, "strikethrough": False,
                            "underline": False, "code": False, "color": "default"}}


def person(number):
    return {"object": "user", "id": f"50000000-0000-4000-8000-{number:012x}",
            "type": "person", "name": "Pessoa sintética " + str(number),
            "person": {}}


def page(ident, parent, properties):
    return {"object": "page", "id": ident, "parent": parent,
            "created_time": STAMP, "last_edited_time": STAMP,
            "in_trash": False, "is_archived": False, "properties": properties,
            "icon": None, "cover": None, "url": "https://www.notion.so/" + ident,
            "public_url": None}


def block(ident, parent, kind, payload, *, has_children=False):
    return {"object": "block", "id": ident, "parent": parent, "type": kind,
            kind: payload, "has_children": has_children, "in_trash": False,
            "created_time": STAMP, "last_edited_time": STAMP}


class SyntheticNotionClient:
    """All responses are local JSON; request records contain no auth credentials."""

    def __init__(self, *, batch_size=1):
        self.batch_size = batch_size
        self.calls = []
        self.traversals = 0
        self.on_response = None
        self.schema = {
            "object": "data_source", "id": DATA_SOURCE_ID,
            "parent": {"type": "database_id", "database_id": DATABASE_ID},
            "in_trash": False, "is_archived": False,
            "created_time": STAMP, "last_edited_time": STAMP,
            "title": [rich("TODO sintético")],
            "properties": {
                "Name": {"id": "title", "name": "Name", "type": "title", "title": {}},
                "Notes": {"id": "a%3Ab", "name": "Notes", "type": "rich_text", "rich_text": {}},
                "Owner": {"id": "owner", "name": "Owner", "type": "people", "people": {}},
                "State": {"id": "state", "name": "State", "type": "select",
                          "select": {"options": [{"id": "pending", "name": "Pending", "color": "gray"}]}},
                "Key": {"id": "key", "name": "Key", "type": "unique_id",
                        "unique_id": {"prefix": "LAB"}},
            },
        }
        owners = [person(n) for n in range(1, 27)]
        self.pages = {}
        self.property_values = {}
        for ident, number in ((PAGE_ONE, 1), (PAGE_TWO, 2)):
            title = [rich("Tarefa "), rich(str(number))]
            notes = [rich("Preservar conteúdo — ação " + str(number)), rich(" e relações.")]
            properties = {
                "Name": {"id": "title", "type": "title", "title": title[:1]},
                "Notes": {"id": "a%3Ab", "type": "rich_text", "rich_text": notes[:1]},
                "Owner": {"id": "owner", "type": "people", "people": owners[:25]},
                "State": {"id": "state", "type": "select",
                          "select": {"id": "pending", "name": "Pending", "color": "gray"}},
                "Key": {"id": "key", "type": "unique_id",
                        "unique_id": {"prefix": "LAB", "number": number}},
            }
            self.pages[ident] = page(ident, {"type": "data_source_id",
                                          "data_source_id": DATA_SOURCE_ID}, properties)
            for prop_id, kind, values in (("title", "title", title), ("a%3Ab", "rich_text", notes),
                                           ("owner", "people", owners)):
                self.property_values[(ident, prop_id)] = (kind, deepcopy(values))
        self.roots = [PAGE_ONE, PAGE_TWO]
        self.pages[CHILD_PAGE] = page(CHILD_PAGE, {"type": "page_id", "page_id": PAGE_ONE}, {
            "title": {"id": "title", "type": "title", "title": [rich("Detalhes")]}
        })
        self.property_values[(CHILD_PAGE, "title")] = ("title", [rich("Detalhes")])
        self.blocks = {
            PAGE_ONE: [
                block(BLOCK_ONE, {"type": "page_id", "page_id": PAGE_ONE}, "toggle",
                      {"rich_text": [rich("Checklist")], "color": "default"}, has_children=True),
                block(CHILD_PAGE, {"type": "page_id", "page_id": PAGE_ONE}, "child_page",
                      {"title": "Detalhes"}),
            ],
            BLOCK_ONE: [
                block(BLOCK_TWO, {"type": "block_id", "block_id": BLOCK_ONE}, "paragraph",
                      {"rich_text": [rich("Verificar acentos: ação, órgão e recuperação.")],
                       "color": "default"}),
            ],
            PAGE_TWO: [
                block(BLOCK_THREE, {"type": "page_id", "page_id": PAGE_TWO}, "code",
                      {"rich_text": [rich("print('synthetic only')")],
                       "caption": [], "language": "python"}),
            ],
            CHILD_PAGE: [
                block(BLOCK_FOUR, {"type": "page_id", "page_id": CHILD_PAGE}, "paragraph",
                      {"rich_text": [rich("Conteúdo da página filha.")], "color": "default"}),
            ],
        }

    def _list(self, values, params, *, kind, metadata=None):
        cursor = params.get("start_cursor")
        start = 0 if cursor is None else int(cursor.removeprefix("cursor-"))
        end = min(start + self.batch_size, len(values))
        more = end < len(values)
        result = {"object": "list", "type": kind, "results": deepcopy(values[start:end]),
                  "has_more": more, "next_cursor": f"cursor-{end}" if more else None}
        if metadata is not None:
            result["property_item"] = {**metadata,
                "next_url": "https://api.notion.com/ignored-next-url" if more else None}
        return result

    def request(self, method, path, *, query=None, payload=None):
        call = {"method": method, "path": path, "query": deepcopy(query),
                "payload": deepcopy(payload)}
        self.calls.append(call)
        if method == "GET" and path == f"/v1/data_sources/{DATA_SOURCE_ID}":
            self.traversals += 1
            response = deepcopy(self.schema)
        elif method == "POST" and path == f"/v1/data_sources/{DATA_SOURCE_ID}/query":
            response = self._list([self.pages[ident] for ident in self.roots],
                                  payload or {}, kind="page_or_data_source")
            response["request_status"] = {"type": "complete"}
        elif method == "GET" and path.startswith("/v1/pages/") and "/properties/" in path:
            ident, prop_id = path[len("/v1/pages/"):].split("/properties/")
            kind, values = self.property_values[(ident, prop_id)]
            items = [{"object": "property_item", "id": prop_id, "type": kind, kind: value}
                     for value in values]
            response = self._list(items, query or {}, kind="property_item",
                                  metadata={"id": prop_id, "type": kind, kind: {}})
        elif method == "GET" and path.startswith("/v1/pages/"):
            response = deepcopy(self.pages[path.removeprefix("/v1/pages/")])
        elif method == "GET" and path.startswith("/v1/blocks/") and path.endswith("/children"):
            ident = path[len("/v1/blocks/"):-len("/children")]
            response = self._list(self.blocks.get(ident, []), query or {}, kind="block")
        else:
            raise AssertionError("Unexpected synthetic API request")
        return self.on_response(call, response) if self.on_response is not None else response


def synthetic_snapshot(*, producer_sha="a" * 40):
    return snapshot_module.collect_snapshot(
        SyntheticNotionClient(), data_source_id=DATA_SOURCE_ID, database_id=DATABASE_ID,
        producer_sha=producer_sha, now=datetime(2026, 10, 19, 12, tzinfo=timezone.utc))


def fake_client(*, batch_size=1):
    return SyntheticNotionClient(batch_size=batch_size)
