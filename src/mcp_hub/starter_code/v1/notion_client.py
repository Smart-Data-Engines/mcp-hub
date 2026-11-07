"""Bounded Notion reads, with fixed routes and explicit pagination/truncation."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID

import httpx

from mcp_hub.models import HubError

API = "https://api.notion.com"
API_VERSION = "2026-03-11"
MAX_RESPONSE = 2 * 1024 * 1024
MAX_ITEM = 6000
MAX_WIRE = 48000


def connection(values: dict[str, Any]) -> str:
    token = values.get("token")
    if not isinstance(token, str) or not token.strip():
        raise HubError("Add a Notion connection token", 422)
    token = token.strip()
    if len(token) > 4096 or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
        raise HubError("Notion token must be a single valid token without spaces", 422)
    return token


def identifier(value: str) -> str:
    try:
        if not isinstance(value, str) or len(value) not in {32, 36}:
            raise ValueError
        return str(UUID(value))
    except ValueError as exc:
        raise HubError(
            "Use a Notion page, block, database or data source ID from a read result", 422
        ) from exc


def paging(limit: int, cursor: str) -> dict[str, Any]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise HubError("Limit must be between 1 and 20", 422)
    if (
        not isinstance(cursor, str)
        or len(cursor) > 512
        or any(ord(c) < 33 or ord(c) > 126 for c in cursor)
    ):
        raise HubError("Use the next_cursor returned by the previous read", 422)
    return {"page_size": limit, **({"start_cursor": cursor} if cursor else {})}


async def request(
    client: httpx.AsyncClient,
    token: str,
    operation: str,
    *,
    item_id: str = "",
    limit: int = 10,
    cursor: str = "",
    query: str = "",
) -> dict[str, Any]:
    token = connection({"token": token})
    if operation not in {"user", "search", "page", "block", "blocks", "database", "query"}:
        raise HubError("Unsupported Notion starter operation", 422)
    listing = operation in {"search", "blocks", "query"}
    parameters = paging(limit, cursor) if listing else {}
    if operation not in {"user", "search"}:
        item_id = identifier(item_id)
    paths = {
        "user": "/v1/users/me",
        "search": "/v1/search",
        "page": f"/v1/pages/{item_id}",
        "block": f"/v1/blocks/{item_id}",
        "blocks": f"/v1/blocks/{item_id}/children",
        "database": f"/v1/databases/{item_id}",
        "query": f"/v1/data_sources/{item_id}/query",
    }
    if operation == "search":
        if not isinstance(query, str) or len(query) > 200:
            raise HubError("Search title must be at most 200 characters", 422)
        if query:
            parameters["query"] = query
    # POST is used only by Notion's read-only search and data-source query APIs.
    method = "POST" if operation in {"search", "query"} else "GET"
    headers = {
        "Authorization": "Bearer " + token,
        "Notion-Version": API_VERSION,
        "Accept-Encoding": "identity",
    }
    try:
        async with client.stream(
            method,
            API + paths[operation],
            headers=headers,
            follow_redirects=False,
            timeout=15,
            params=parameters if method == "GET" else None,
            json=parameters if method == "POST" else None,
        ) as response:
            if response.status_code == 401:
                raise HubError(
                    "Notion rejected this token. Check that the connection token is current", 422
                )
            if response.status_code == 429:
                raise HubError("Notion API rate limit reached. Try again shortly", 429)
            if response.status_code in {403, 404}:
                raise HubError(
                    "Notion content is unavailable. Give the connection Read content access and share the page or database with it",
                    422,
                )
            if response.status_code == 400:
                raise HubError(
                    "Notion could not accept this read. Check the selected item and pagination cursor",
                    422,
                )
            if response.status_code != 200:
                raise HubError("Notion could not complete this read. Try again shortly", 502)
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise HubError("Notion returned an unsupported compressed response", 502)
            payload = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=65536):
                if len(payload) + len(chunk) > MAX_RESPONSE:
                    raise HubError("Notion response is too large. Request fewer results", 413)
                payload.extend(chunk)
            value = json.loads(payload)
            expected = (
                "list"
                if listing
                else {"user": "user", "page": "page", "block": "block", "database": "database"}[
                    operation
                ]
            )
            if not isinstance(value, dict) or value.get("object") != expected:
                raise HubError("Notion returned an unexpected response", 502)
            if listing:
                rows = value.get("results")
                if (
                    not isinstance(rows, list)
                    or len(rows) > limit
                    or any(not isinstance(row, dict) for row in rows)
                    or not isinstance(value.get("has_more"), bool)
                ):
                    raise HubError("Notion returned an unexpected result page", 502)
                next_cursor = value.get("next_cursor")
                if next_cursor is not None and (
                    not isinstance(next_cursor, str)
                    or len(next_cursor) > 512
                    or any(ord(c) < 33 or ord(c) > 126 for c in next_cursor)
                ):
                    raise HubError("Notion returned an invalid pagination cursor", 502)
                if value["has_more"] and not next_cursor:
                    raise HubError("Notion omitted the next cursor for an incomplete result", 502)
            return value
    except (httpx.HTTPError, ValueError, UnicodeError, RecursionError) as exc:
        raise HubError(
            "Notion could not be reached or returned an invalid response. Try again", 502
        ) from exc


def text(parts: Any) -> str:
    if not isinstance(parts, list):
        return ""
    values = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        value = part.get("plain_text")
        if not isinstance(value, str):
            nested = part.get("text")
            value = nested.get("content", "") if isinstance(nested, dict) else ""
        if isinstance(value, str):
            values.append(value)
    return "".join(values)


def simple_shape(value: Any) -> bool:
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 12 or nodes > 512:
            return False
        if isinstance(item, dict):
            if len(item) > 512:
                return False
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            if len(item) > 512:
                return False
            pending.extend((v, depth + 1) for v in item)
    return True


def bounded_item(value: dict[str, Any], max_chars: int = MAX_ITEM) -> dict[str, Any]:
    result = {"data": value, "truncated": False}
    if simple_shape(value) and len(json.dumps(result)) <= max_chars:
        return result
    title = text(value.get("title"))
    properties = value.get("properties")
    if isinstance(properties, dict):
        title = next(
            (
                text(p.get("title"))
                for p in properties.values()
                if isinstance(p, dict) and p.get("type") == "title"
            ),
            title,
        )
    kind = value.get("type")
    details = value.get(kind, {}) if isinstance(kind, str) else {}
    excerpt = text(details.get("rich_text")) if isinstance(details, dict) else ""
    summary = {
        "id": "".join(c for c in str(value.get("id", ""))[:64] if 32 <= ord(c) <= 126),
        "object": "".join(c for c in str(value.get("object", ""))[:30] if 32 <= ord(c) <= 126),
        "type": "".join(c for c in str(kind or "")[:60] if 32 <= ord(c) <= 126),
        "has_children": bool(value.get("has_children")),
        "title": title[:500],
        "excerpt": excerpt[:2000],
    }
    result = {
        "data": summary,
        "truncated": True,
        "note": "This item exceeds the starter output limit. Use get_block for one block, or open the full item in Notion.",
    }
    while len(json.dumps(result)) > max_chars:
        if not summary["excerpt"] and not summary["title"]:
            raise HubError("Notion item metadata exceeds the starter output limit", 413)
        summary["excerpt"] = str(summary["excerpt"])[: len(str(summary["excerpt"])) // 2]
        summary["title"] = str(summary["title"])[: len(str(summary["title"])) // 2]
    return result


def result_page(value: dict[str, Any]) -> dict[str, Any]:
    result = {
        "items": [bounded_item(row) for row in value["results"]],
        "has_more": value["has_more"],
        "next_cursor": value.get("next_cursor"),
        "note": "One page of results. Pass next_cursor to the next call when has_more is true.",
    }
    if isinstance(value.get("request_status"), dict):
        result["request_status"] = {
            key: str(value["request_status"].get(key, ""))[:200]
            for key in ["type", "incomplete_reason"]
        }
    # Budget the MCP envelope, not just compact provider JSON. FastMCP pretty
    # prints text and may also include structuredContent. Keep every item ID,
    # its explicit truncation flag and the provider cursor while reducing text.
    budget = MAX_ITEM
    while (
        len(
            json.dumps(
                {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "structuredContent": result,
                }
            )
        )
        > MAX_WIRE
    ):
        if budget == 512:
            raise HubError(
                "Notion result cannot fit the starter output budget. Request fewer items", 413
            )
        budget = max(512, budget // 2)
        result["items"] = [bounded_item(row, budget) for row in value["results"]]
    return result


async def test_connection(client: httpx.AsyncClient, values: dict[str, Any]) -> dict:
    token = connection(values)
    try:
        async with asyncio.timeout(25):
            user = await request(client, token, "user")
            found = await request(client, token, "search", limit=1)
    except TimeoutError as exc:
        raise HubError("The Notion connection test timed out. Try again shortly", 504) from exc
    if (
        user.get("type") != "bot"
        or (user.get("name") is not None and not isinstance(user.get("name"), str))
        or not isinstance(user.get("bot"), dict)
    ):
        raise HubError("Notion returned an unexpected connection identity", 502)
    account = (user.get("name") or "Notion connection")[:200]
    visible = bool(found["results"])
    return {
        "ok": True,
        "account": account,
        "message": f"Connected as {account}",
        "shared_content_found": visible,
        "checked": ["connection_identity", "search_read_access"],
        "note": "Connection identity and search read access verified. "
        + (
            "Only content accessible to this connection can be read."
            if visible
            else "Search returned no pages or data sources. Share a page with this connection in Notion and allow time for search indexing."
        ),
    }
