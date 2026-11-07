import json

import httpx
import pytest

from mcp_hub import starters
from mcp_hub.models import HubError, ServerDefinition
from mcp_hub.starter_code.v1 import notion, notion_client

IDENTITY = {
    "_hub_user_id": "person",
    "_hub_username": "person@example.test",
    "_hub_principal": "human",
}
ITEM = "12345678-1234-4234-8234-123456789abc"
TOKEN = "synthetic-notion-token"


async def test_notion_tools_use_fixed_read_routes_each_callers_token_and_pagination(monkeypatch):
    calls = []

    def provider(request):
        calls.append(request)
        assert request.url.host == "api.notion.com"
        assert request.headers["Notion-Version"] == "2026-03-11"
        path = request.url.path
        if path.endswith(("/search", "/query", "/children")):
            assert request.method == ("GET" if path.endswith("/children") else "POST")
            return httpx.Response(
                200,
                json={
                    "object": "list",
                    "results": [{"id": ITEM, "object": "page"}],
                    "has_more": True,
                    "next_cursor": "opaque-next-cursor",
                },
            )
        assert request.method == "GET"
        return httpx.Response(
            200, json={"object": "database" if "/databases/" in path else "page", "id": ITEM}
        )

    monkeypatch.setattr(
        notion, "client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(provider))
    )
    monkeypatch.setenv("NOTION_TOKEN", "synthetic-shared-token")
    first = {**IDENTITY, "token": TOKEN}
    second = {**IDENTITY, "token": "synthetic-second-token"}
    page = await notion.search("Roadmap", 2, credentials=first)
    assert page["has_more"] and page["next_cursor"] == "opaque-next-cursor"
    await notion.get_page(ITEM.replace("-", ""), second)
    await notion.list_blocks(ITEM, 2, "opaque-next-cursor", first)
    await notion.get_database(ITEM, second)
    await notion.query_data_source(ITEM, 2, "opaque-next-cursor", first)
    assert [r.url.path for r in calls] == [
        "/v1/search",
        f"/v1/pages/{ITEM}",
        f"/v1/blocks/{ITEM}/children",
        f"/v1/databases/{ITEM}",
        f"/v1/data_sources/{ITEM}/query",
    ]
    assert [r.headers["Authorization"] for r in calls] == [
        "Bearer " + TOKEN,
        "Bearer synthetic-second-token",
        "Bearer " + TOKEN,
        "Bearer synthetic-second-token",
        "Bearer " + TOKEN,
    ]
    assert json.loads(calls[0].content) == {"query": "Roadmap", "page_size": 2}
    assert calls[2].url.params["start_cursor"] == "opaque-next-cursor"
    assert json.loads(calls[4].content) == {"page_size": 2, "start_cursor": "opaque-next-cursor"}
    assert notion.account(IDENTITY) == "synthetic-shared-token"
    with pytest.raises(HubError):
        notion.account({**IDENTITY, "token": ""})
    for credentials in [
        None,
        {},
        {"_hub_username": "spoofed"},
        {**IDENTITY, "_hub_principal": "anonymous"},
    ]:
        with pytest.raises(ValueError, match="Sign in"):
            notion.account(credentials)


async def test_all_notion_tools_declare_read_only_and_explicit_caller_contract():
    tools = await notion.mcp.list_tools()
    assert {t.name for t in tools} == {
        "search",
        "get_page",
        "list_blocks",
        "get_database",
        "query_data_source",
    }
    for tool in tools:
        assert tool.annotations.readOnlyHint and not tool.annotations.destructiveHint
        assert "credentials" in tool.inputSchema["properties"]


@pytest.mark.parametrize(
    "operation,args",
    [
        (notion.get_page, {"page_id": "../../users/me"}),
        (notion.get_database, {"database_id": "https://other.example.test/private"}),
        (notion.query_data_source, {"data_source_id": ITEM, "limit": 21}),
        (notion.list_blocks, {"block_id": ITEM, "limit": True}),
        (notion.search, {"cursor": "bad\ncursor"}),
        (notion.search, {"cursor": "x" * 513}),
        (notion.search, {"query": "x" * 201}),
    ],
)
async def test_invalid_notion_inputs_never_contact_a_provider(operation, args, monkeypatch):
    def forbidden(request):
        raise AssertionError("Invalid tool input must not reach a provider")

    monkeypatch.setattr(
        notion, "client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(forbidden))
    )
    with pytest.raises(HubError) as error:
        await operation(credentials={**IDENTITY, "token": TOKEN}, **args)
    assert error.value.status == 422


@pytest.mark.parametrize(
    "status,expected",
    [(400, 422), (401, 422), (403, 422), (404, 422), (429, 429), (500, 502), (302, 502)],
)
async def test_notion_errors_and_redirects_do_not_expose_provider_body_or_token(status, expected):
    calls = []

    def provider(request):
        calls.append(request)
        return httpx.Response(status, text=TOKEN, headers={"Location": "http://127.0.0.1/private"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
        with pytest.raises(HubError) as error:
            await notion_client.request(client, TOKEN, "page", item_id=ITEM)
    assert error.value.status == expected and TOKEN not in str(error.value)
    assert len(calls) == 1 and calls[0].url.host == "api.notion.com"


@pytest.mark.parametrize(
    "value",
    [
        {"object": "list", "results": [], "has_more": True, "next_cursor": None},
        {"object": "list", "results": ["not-an-object"], "has_more": False},
        {"object": "list", "results": [], "has_more": "false"},
        {"object": "page", "id": ITEM},
    ],
)
async def test_malformed_notion_pages_are_not_reported_as_complete(value):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=value))
    ) as client:
        with pytest.raises(HubError) as error:
            await notion_client.request(client, TOKEN, "search")
    assert error.value.status == 502


async def test_oversized_notion_response_is_rejected_before_parsing():
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"x" * (notion_client.MAX_RESPONSE + 1))
        )
    ) as client:
        with pytest.raises(HubError) as error:
            await notion_client.request(client, TOKEN, "search")
    assert error.value.status == 413


def test_output_budget_marks_truncation_and_preserves_pagination_and_provider_status():
    value = {
        "object": "block",
        "id": ITEM,
        "type": "paragraph",
        "has_children": True,
        "paragraph": {"rich_text": [{"plain_text": '🧪"' * 10000}]},
    }
    limited = notion_client.bounded_item(value)
    assert limited["truncated"] and limited["data"]["has_children"]
    assert len(json.dumps(limited)) <= notion_client.MAX_ITEM
    result = notion_client.result_page(
        {
            "results": [value],
            "has_more": True,
            "next_cursor": "continue",
            "request_status": {
                "type": "incomplete",
                "incomplete_reason": "query_result_limit_reached",
            },
        }
    )
    assert result["has_more"] and result["next_cursor"] == "continue"
    assert result["request_status"]["type"] == "incomplete"
    original = {
        "object": "page",
        "id": ITEM,
        "properties": {"Count": {"type": "number", "number": 19}},
    }
    assert notion_client.bounded_item(original) == {"data": original, "truncated": False}
    assert (
        notion_client.text([{"text": "malformed"}, None, {"text": {"content": "valid"}}]) == "valid"
    )


def test_notion_source_bundle_is_complete_and_existing_starter_snapshots_are_unchanged():
    definition = ServerDefinition(
        name="example", owner="alice", starter_id="notion", starter_version="1.0.0"
    )
    snapshot = starters.snapshot(definition)
    assert (
        "notion_client.py" in snapshot.files
        and "httpx==0.28.1" in snapshot.files["requirements.txt"]
    )
    assert snapshot.files["env.yaml"] == "env: [NOTION_TOKEN]\nuser_env: [token]\n"
    assert "serve(mcp)" in snapshot.files["server.py"]
    for kind, expected in {
        "demo": "409946ac54cfecd98455063c8872e9a239e4eedb",
        "github": "9e457dc48699c0e59b6a33300296d15a6b0a03b5",
    }.items():
        legacy = definition.model_copy(update={"starter_id": kind})
        assert starters.snapshot(legacy).commit == expected
