import asyncio
import json

from mcp_hub.models import Principal
from mcp_hub.store import dumps


async def test_unauthenticated_mcp_challenges_with_discovery(harness):
    response = await harness.client.post("/mcp", json={})
    assert response.status_code == 401
    assert "oauth-protected-resource/mcp" in response.headers["www-authenticate"]
    assert (await harness.client.get("/.well-known/oauth-authorization-server")).json()[
        "code_challenge_methods_supported"
    ] == ["S256"]
    assert (await harness.client.get("/admin/api/users")).status_code == 401


async def test_listing_is_cached_filters_schema_and_has_version(harness):
    response = await harness.rpc("tools/list")
    assert response.status_code == 200, response.text
    tools = response.json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == {
        "alpha.lookup",
        "alpha.create_ticket",
        "alpha.delete_ticket",
        "hub.discover_tools",
    }
    assert "credentials" not in dumps(tools)
    assert "_hub_username" not in dumps(tools)
    assert int(response.headers["x-hub-catalog-version"]) > 0
    assert harness.session.calls == []


async def test_call_strips_spoofed_identity_redacts_and_audits_once(harness):
    response = await harness.rpc(
        "tools/call",
        {
            "name": "alpha.lookup",
            "arguments": {
                "query": "where",
                "credentials": {"password": "forged", "_hub_username": "admin"},
                "_hub_username": "administrator",
            },
        },
    )
    result = response.json()["result"]
    assert not result["isError"], response.text
    forwarded = harness.session.calls[0][1]
    assert forwarded["credentials"]["_hub_username"] == "alice@example.test"
    assert "_hub_username" not in forwarded
    assert "forged" not in dumps(forwarded)
    assert "very-private-password" not in response.text
    events = await harness.hub.redis.lrange(harness.hub.store.key("audit:spool"), 0, -1)
    assert len(events) == 1
    event = json.loads(events[0])
    assert event["request_id"] == result["_meta"]["hub/provenance"]["request_id"]
    assert response.headers["x-request-id"] == event["request_id"]
    assert float(response.headers["x-hub-overhead-ms"]) >= 0
    assert event["arguments"] == {"query": "where"}


async def test_acl_capabilities_and_revocation_apply_to_next_request(harness):
    hub = harness.hub
    bob = Principal(id="bob", username="bob")
    await hub.acl.provision(bob)
    await hub.redis.hset(
        hub.store.key("acl:groups"), "default", dumps({"servers": {"alpha": ["read"]}})
    )
    token = (await hub.oauth._issue(bob, "test"))["access_token"]
    headers = {"Authorization": "Bearer " + token}
    result = (await harness.rpc("tools/list", headers=headers)).json()["result"]
    assert [tool["name"] for tool in result["tools"]] == ["alpha.lookup", "hub.discover_tools"]
    result = (
        await harness.rpc(
            "tools/call", {"name": "alpha.create_ticket", "arguments": {"query": "hello"}}, headers
        )
    ).json()["result"]
    assert result["isError"]
    assert harness.session.calls == []
    await hub.acl.change_user("bob", "deny", "alpha")
    result = (await harness.rpc("tools/list", headers=headers)).json()["result"]
    assert len(result["tools"]) == 1
    await hub.acl.change_user("bob", "grant", {"server": "alpha", "caps": ["read"]})
    assert len((await harness.rpc("tools/list", headers=headers)).json()["result"]["tools"]) == 2
    await hub.oauth.revoke_principal("bob")
    assert (await harness.rpc("tools/list", headers=headers)).status_code == 401


async def test_idempotency_concurrent_writes_produce_one_upstream_effect(harness):
    responses = await asyncio.gather(
        *(
            harness.rpc(
                "tools/call", {"name": "alpha.create_ticket", "arguments": {"query": "same-ticket"}}
            )
            for _ in range(12)
        )
    )
    assert all(response.status_code == 200 for response in responses)
    assert len(harness.session.calls) == 1
    events = [
        json.loads(value)
        for value in await harness.hub.redis.lrange(harness.hub.store.key("audit:spool"), 0, -1)
    ]
    assert len(events) == 12
    for response, _event in zip(responses, events, strict=True):
        # Concurrent completion order can differ: match IDs as sets below.
        assert "hub/provenance" in response.json()["result"]["_meta"]
    assert {event["request_id"] for event in events} == {
        response.json()["result"]["_meta"]["hub/provenance"]["request_id"] for response in responses
    }


async def test_rate_guardrail_and_daily_budget_are_audited(harness):
    harness.hub.settings.hub_tool_rate_limit = 1
    first = await harness.rpc("tools/call", {"name": "alpha.lookup", "arguments": {"query": "one"}})
    second = await harness.rpc(
        "tools/call", {"name": "alpha.lookup", "arguments": {"query": "one"}}
    )
    assert not first.json()["result"]["isError"]
    assert second.json()["result"]["_meta"]["hub/error"] == "rate_limited"
    assert int(second.headers["retry-after"]) > 0
    assert await harness.hub.redis.llen(harness.hub.store.key("audit:spool")) == 2


async def test_guardrail_blocks_before_upstream(harness):
    harness.hub.gateway.rules = [
        {"tools": ["alpha.lookup"], "keys": ["query"], "contains": ["DELETE /production"]}
    ]
    result = (
        await harness.rpc(
            "tools/call",
            {"name": "alpha.lookup", "arguments": {"query": "please DELETE /production"}},
        )
    ).json()["result"]
    assert result["_meta"]["hub/error"] == "blocked_content"
    assert not harness.session.calls


async def test_credentials_modes_precedence_and_ciphertext(harness):
    hub = harness.hub
    await hub.credentials.save("alice", "alpha", {"password": "secret-from-store"})
    raw = await hub.redis.get(hub.store.key("creds:alice:alpha"))
    assert "secret-from-store" not in raw
    await harness.rpc(
        "tools/call",
        {"name": "alpha.lookup", "arguments": {"query": "one"}},
        {"X-Hub-Credentials": dumps({"alpha": {"password": "header-secret"}})},
    )
    assert harness.session.calls[-1][1]["credentials"]["password"] == "header-secret"
    await hub.credentials.set_mode("alice", "alpha", True)
    await hub.credentials.delete("alice", "alpha")
    result = (
        await harness.rpc("tools/call", {"name": "alpha.lookup", "arguments": {"query": "two"}})
    ).json()["result"]
    assert result["_meta"]["hub/error"] == "credentials_required"
    assert len(harness.session.calls) == 1


async def test_unknown_tools_are_actionable_and_private_catalog_is_hidden(harness):
    result = (await harness.rpc("tools/call", {"name": "absent.lookup", "arguments": {}})).json()[
        "result"
    ]
    assert "alpha" in result["content"][0]["text"]
    assert "hub.discover_tools" in result["content"][0]["text"]
    result = (await harness.rpc("tools/call", {"name": "alpha.renamed", "arguments": {}})).json()[
        "result"
    ]
    assert "renamed" in result["content"][0]["text"]


async def test_admin_safety_and_credential_api_do_not_return_secrets(harness):
    headers = harness.headers
    response = await harness.client.delete("/admin/api/admins/alice", headers=headers)
    assert response.status_code == 409
    assert (
        await harness.client.delete("/admin/api/groups/default", headers=headers)
    ).status_code == 409
    assert (
        await harness.client.post(
            "/credentials",
            headers=headers,
            json={"service": "alpha", "credentials": {"password": "hidden"}},
        )
    ).status_code == 204
    response = await harness.client.get("/credentials", headers=headers)
    assert response.json()["services"] == ["alpha"]
    assert "hidden" not in response.text


async def test_registration_fails_closed_and_rejects_ssrf_schemes(harness):
    for url in ("file:///etc/passwd", "gopher://localhost", "http://user:secret@localhost/mcp"):
        response = await harness.client.post(
            "/register",
            json={"name": "new", "url": url},
            headers={"x-hub-secret": harness.hub.settings.hub_registration_secret},
        )
        assert response.status_code == 400
    response = await harness.client.post(
        "/register", json={"name": "new", "url": "http://localhost/mcp"}
    )
    assert response.status_code == 403


async def test_readiness_and_drain(harness):
    assert (await harness.client.get("/ready")).status_code == 200
    await harness.hub.drain()
    assert (await harness.client.get("/ready")).status_code == 503
    response = await harness.rpc(
        "tools/call", {"name": "alpha.lookup", "arguments": {"query": "one"}}
    )
    assert response.json()["result"]["_meta"]["hub/error"] == "service_shutdown"


async def test_daily_budget_is_shared_across_different_tools(harness):
    harness.hub.settings.hub_daily_call_budget = 1
    first = await harness.rpc("tools/call", {"name": "alpha.lookup", "arguments": {"query": "one"}})
    second = await harness.rpc(
        "tools/call", {"name": "alpha.create_ticket", "arguments": {"query": "different tool"}}
    )
    assert not first.json()["result"]["isError"]
    assert second.json()["result"]["isError"]
    assert "Daily call budget" in second.json()["result"]["content"][0]["text"]
    assert len(harness.session.calls) == 1
    assert await harness.hub.redis.llen(harness.hub.store.key("audit:spool")) == 2
