import json

import httpx
import pytest

from mcp_hub.models import Principal
from tests.integration.test_starters import create

BASE = "/admin/api/servers-dynamic/notion-example"
TOKEN = "synthetic-notion-personal"


async def included(harness, monkeypatch):
    value = await create(harness, monkeypatch, "notion", "notion-example")
    assert value["policy"] == "user_only" and value["user_env_fields"] == ["token"]


async def test_notion_personal_token_is_encrypted_hidden_and_blank_preserves_it(
    harness, monkeypatch
):
    await included(harness, monkeypatch)
    for values in [{"token": TOKEN}, {"token": ""}]:
        response = await harness.client.patch(
            BASE + "/starter-connection", json={"values": values}, headers=harness.headers
        )
        assert response.status_code == 204
    response = await harness.client.get(BASE + "/starter-connection", headers=harness.headers)
    assert response.json()["personal"] == {"configured": ["token"]}
    assert response.json()["required_fields"] == ["token"] and TOKEN not in response.text
    encrypted = await harness.hub.redis.get(harness.hub.store.key("creds:alice:notion-example"))
    assert TOKEN not in encrypted
    assert await harness.hub.credentials.personal("alice", "notion-example") == {"token": TOKEN}
    rejected = await harness.client.patch(
        BASE + "/starter-connection",
        json={"values": {"repository": "unrelated/repo"}},
        headers=harness.headers,
    )
    assert rejected.status_code == 422
    assert (
        await harness.client.post(
            BASE + "/policy", json={"policy": "both"}, headers=harness.headers
        )
    ).status_code == 422


@pytest.mark.parametrize("visible", [False, True])
@pytest.mark.parametrize("bot_name", [None, TOKEN])
async def test_notion_connection_test_checks_identity_and_search_without_writes(
    harness, monkeypatch, visible, bot_name
):
    await included(harness, monkeypatch)
    await harness.client.patch(
        BASE + "/starter-connection", json={"values": {"token": TOKEN}}, headers=harness.headers
    )
    calls = []

    def provider(request):
        calls.append(request)
        assert (
            request.url.host == "api.notion.com"
            and request.headers["Authorization"] == "Bearer " + TOKEN
        )
        if request.url.path == "/v1/users/me":
            assert request.method == "GET"
            return httpx.Response(
                200, json={"object": "user", "type": "bot", "name": bot_name, "bot": {}}
            )
        assert request.url.path == "/v1/search" and request.method == "POST"
        assert json.loads(request.content) == {"page_size": 1}
        return httpx.Response(
            200,
            json={
                "object": "list",
                "results": [{"object": "page"}] if visible else [],
                "has_more": False,
                "next_cursor": None,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
        monkeypatch.setattr(harness.hub, "http", client)
        response = await harness.client.post(
            BASE + "/starter-connection/test", json={}, headers=harness.headers
        )
    assert response.status_code == 200 and response.json()["shared_content_found"] is visible
    assert response.json()["connection"] == "personal" and TOKEN not in response.text
    assert len(calls) == 2
    if not visible:
        assert "Share a page" in response.json()["note"]


async def test_notion_shared_connection_is_admin_only_and_personal_preference_is_preserved(
    harness, monkeypatch
):
    await included(harness, monkeypatch)
    response = await harness.client.patch(
        BASE + "/starter-connection",
        json={"policy": "global_only", "values": {"token": TOKEN}},
        headers=harness.headers,
    )
    assert response.status_code == 204
    assert await harness.hub.credentials.global_env("notion-example") == {"NOTION_TOKEN": TOKEN}
    await harness.hub.credentials.set_mode("alice", "notion-example", True)
    response = await harness.client.post(
        BASE + "/starter-connection/test", json={}, headers=harness.headers
    )
    assert response.status_code == 403 and "personal" in response.json()["error"]
    await harness.hub.redis.srem(harness.hub.store.key("acl:admins"), "alice")
    for method in ["PATCH", "DELETE"]:
        response = await harness.client.request(
            method,
            BASE + "/starter-connection",
            json={"policy": "global_only", "values": {"token": "changed"}}
            if method == "PATCH"
            else None,
            headers=harness.headers,
        )
        assert response.status_code == 403
    info = (await harness.client.get(BASE + "/starter-connection", headers=harness.headers)).json()
    assert info["shared"] == {"configured": []}


async def test_notion_read_access_does_not_expose_another_persons_connection(harness, monkeypatch):
    await included(harness, monkeypatch)
    await harness.client.patch(
        BASE + "/starter-connection", json={"values": {"token": TOKEN}}, headers=harness.headers
    )
    bob = Principal(id="bob", username="bob@example.test", management=True)
    await harness.hub.acl.provision(bob)
    headers = {
        "Authorization": "Bearer "
        + (await harness.hub.oauth._issue(bob, "test-client"))["access_token"]
    }
    assert (
        await harness.client.get(BASE + "/starter-connection", headers=headers)
    ).status_code == 403
    definition = await harness.hub.runtime.definition("notion-example")
    definition.visibility, definition.shared_with = "shared", ["bob"]
    await harness.hub.runtime.save(definition, fields={"visibility", "shared_with"})
    key = harness.hub.store.key("acl:users")
    user = json.loads(await harness.hub.redis.hget(key, "bob"))
    user["grants"]["notion-example"] = ["read"]
    await harness.hub.redis.hset(key, "bob", json.dumps(user))
    info = await harness.client.get(BASE + "/starter-connection", headers=headers)
    assert info.json()["personal"]["configured"] == [] and TOKEN not in info.text
    assert (
        await harness.client.post(BASE + "/starter-connection/test", json={}, headers=headers)
    ).status_code == 403
    response = await harness.client.patch(
        BASE + "/starter-connection",
        json={"values": {"token": "synthetic-bob-token"}},
        headers=headers,
    )
    assert response.status_code == 204
    assert await harness.hub.credentials.personal("alice", "notion-example") == {"token": TOKEN}
    assert await harness.hub.credentials.personal("bob", "notion-example") == {
        "token": "synthetic-bob-token"
    }
