import asyncio

import pytest

from mcp_hub.models import Principal, ServerDefinition
from mcp_hub.store import digest


async def test_stale_replica_cannot_publish_a_catalog_after_registry_changes(harness):
    store = harness.hub.store
    generation, _ = await store.registered_snapshot()
    current = await store.catalog()
    await store.register("new", {"name": "new", "url": "http://new/mcp", "code_version": "1"}, 60)
    assert await store.publish_catalog({}, generation=generation) == -1
    assert await store.catalog() == current
    fresh, _ = await store.registered_snapshot()
    assert await store.publish_catalog({"new": {"tools": []}}, generation=fresh) > 0


async def test_concurrent_status_and_policy_updates_preserve_both(harness):
    store = harness.hub.store
    definition = ServerDefinition(name="concurrent", owner="alice")
    await store.save_dynamic(definition.name, definition.model_dump(), create=True)
    await asyncio.gather(
        store.patch_dynamic(definition.name, {"status": "running"}),
        store.patch_dynamic(definition.name, {"policy": "user_only"}),
    )
    value = (await store.dynamic())[definition.name]
    assert value["status"] == "running" and value["policy"] == "user_only"


async def test_retired_server_name_cannot_capture_another_owners_grants_or_credentials(harness):
    store = harness.hub.store
    first = ServerDefinition(name="retired", owner="first")
    assert await store.save_dynamic("retired", first.model_dump(), create=True) == 1
    await store.delete_dynamic("retired")
    assert (
        await store.save_dynamic(
            "retired", first.model_copy(update={"owner": "other"}).model_dump(), create=True
        )
        == -1
    )
    assert await store.save_dynamic("retired", first.model_dump(), create=True) == 1


async def test_late_heartbeat_cannot_revive_a_stopped_managed_server(harness):
    store = harness.hub.store
    definition = ServerDefinition(name="stopped", owner="alice", status="stopping")
    await store.save_dynamic("stopped", definition.model_dump())
    assert not await store.register("stopped", {"name": "stopped", "url": "http://stopped/mcp"}, 60)
    assert "stopped" not in await store.registered()


async def test_alias_discovery_keeps_its_resource_and_rejects_external_audiences(harness):
    response = await harness.client.post("/mcp/public", json={})
    assert (
        response.status_code == 401
        and "oauth-protected-resource/mcp/public" in response.headers["www-authenticate"]
    )
    metadata = (await harness.client.get("/.well-known/oauth-protected-resource/mcp/public")).json()
    assert metadata["resource"] == harness.hub.settings.resource + "/public"
    assert harness.hub.oauth.allows_resource(metadata["resource"])
    assert not harness.hub.oauth.allows_resource("https://other.example/mcp")


async def interactive(harness, principal_id, cookie):
    await harness.hub.store.put(
        "oauth:ui:" + digest(cookie), {"principal_id": principal_id, "csrf": cookie}, ttl=3600
    )
    harness.client.cookies.set("hub_ui", cookie)
    return {"Origin": harness.hub.settings.hub_public_url, "X-Hub-Interactive": cookie}


@pytest.mark.parametrize("idempotency", [True, False])
async def test_human_approval_is_consumed_once_and_cannot_authorize_another_effect(
    harness, idempotency
):
    definition = ServerDefinition(
        name="alpha",
        owner="alice",
        visibility="public",
        approval_required=True,
        idempotency=idempotency,
    )
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    call = {"name": "alpha.delete_ticket", "arguments": {"query": "delete-one"}}
    result = (await harness.rpc("tools/call", call)).json()["result"]
    assert result["_meta"]["hub/error"] == "blocked_approval"
    approval = (await harness.client.get("/admin/api/approvals", headers=harness.headers)).json()[
        "approvals"
    ][0]
    response = await harness.client.post(
        "/admin/api/approvals/" + approval["id"],
        json={"decision": "approve"},
        headers=harness.headers,
    )
    assert response.status_code == 403
    headers = {**harness.headers, **await interactive(harness, "alice", "interactive-alice")}
    assert (
        await harness.client.post(
            "/admin/api/approvals/" + approval["id"], json={"decision": "approve"}, headers=headers
        )
    ).status_code == 200
    assert not (await harness.rpc("tools/call", call)).json()["result"]["isError"]
    next_result = (await harness.rpc("tools/call", call)).json()["result"]
    assert next_result["isError"] is (not idempotency)
    assert len(harness.session.calls) == 1


async def test_four_eyes_policy_change_requires_a_different_authorized_human(harness):
    definition = ServerDefinition(
        name="alpha", owner="alice", visibility="public", approval_required=True
    )
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    await harness.rpc("tools/call", {"name": "alpha.delete_ticket", "arguments": {"query": "one"}})
    approval = (await harness.client.get("/admin/api/approvals", headers=harness.headers)).json()[
        "approvals"
    ][0]
    await harness.hub.store.patch_dynamic("alpha", {"approval_four_eyes": True})
    headers = {**harness.headers, **await interactive(harness, "alice", "alice-browser")}
    assert (
        await harness.client.post(
            "/admin/api/approvals/" + approval["id"], json={"decision": "approve"}, headers=headers
        )
    ).status_code == 403
    bob = Principal(id="bob", username="bob", management=True)
    await harness.hub.acl.provision(bob)
    await harness.hub.acl.change_user("bob", "grant", {"server": "alpha", "caps": ["destructive"]})
    token = (await harness.hub.oauth._issue(bob, "bob-client"))["access_token"]
    headers = {
        "Authorization": "Bearer " + token,
        **await interactive(harness, "bob", "bob-browser"),
    }
    response = await harness.client.post(
        "/admin/api/approvals/" + approval["id"], json={"decision": "approve"}, headers=headers
    )
    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "metadata",
    [{"grant_types": [{}]}, {"token_endpoint_auth_method": {}}, {"redirect_uris": [None]}],
)
async def test_malformed_client_metadata_is_a_protocol_error_not_a_server_error(harness, metadata):
    response = await harness.client.post(
        "/oauth/register", json={"redirect_uris": ["http://localhost/callback"], **metadata}
    )
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/json")
