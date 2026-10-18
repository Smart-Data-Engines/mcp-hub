"""Verify console workflows against actual authorization, not just saved form values."""

import asyncio
import json

import pytest

from mcp_hub.models import HubError, Principal, ServerDefinition


async def person(harness, name):
    principal = Principal(id=name, username=f"{name}@example.test", management=True)
    await harness.hub.acl.provision(principal)
    token = (await harness.hub.oauth._issue(principal, "console-tests"))["access_token"]
    return principal, {"Authorization": "Bearer " + token}


async def private_server(harness, **kwargs):
    definition = ServerDefinition(name="alpha", owner="alice", **kwargs)
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    return definition


async def save(harness, user="bob", mode="grant", caps=None, headers=None, server="alpha"):
    return await harness.client.put(
        f"/admin/api/users/{user}/access/{server}",
        json={"mode": mode, "caps": ["read"] if caps is None else caps},
        headers=headers or harness.headers,
    )


async def listed(harness, headers):
    response = await harness.rpc("tools/list", headers=headers)
    assert response.status_code == 200
    return {tool["name"] for tool in response.json()["result"]["tools"]}


async def test_grant_shares_only_the_chosen_person_and_really_allows_a_tool_call(harness):
    _, bob = await person(harness, "bob")
    _, carol = await person(harness, "carol")
    # Old selected people on a private server must not silently regain access.
    await private_server(harness, shared_with=["carol"], status="running", pinned_ref="v1")
    await harness.hub.acl.change_user("carol", "grant", {"server": "alpha", "caps": ["read"]})
    assert "alpha.lookup" not in await listed(harness, bob)
    result = await save(harness)
    assert result.status_code == 200
    assert result.json()["servers"]["alpha"]["effective_caps"] == ["read"]
    definition = await harness.hub.runtime.definition("alpha")
    assert definition.visibility == "shared" and definition.shared_with == ["bob"]
    assert definition.status == "running" and definition.pinned_ref == "v1"
    assert "alpha.lookup" in await listed(harness, bob)
    assert "alpha.create_ticket" not in await listed(harness, bob)
    assert "alpha.lookup" not in await listed(harness, carol)
    response = await harness.rpc(
        "tools/call", {"name": "alpha.lookup", "arguments": {"query": "allowed"}}, bob
    )
    assert response.status_code == 200 and not response.json()["result"]["isError"]


async def test_block_removes_a_personal_grant_and_inherit_restores_only_group_access(harness):
    _, bob = await person(harness, "bob")
    await private_server(harness)
    await harness.client.put(
        "/admin/api/groups/default", json={"servers": {"alpha": ["read"]}}, headers=harness.headers
    )
    assert (await save(harness, caps=["write"])).status_code == 200
    assert {"alpha.lookup", "alpha.create_ticket"} <= await listed(harness, bob)
    response = await save(harness, mode="block", caps=[])
    assert response.status_code == 200
    assert response.json()["servers"]["alpha"]["personal_grant"] is None
    assert response.json()["servers"]["alpha"]["personal_deny"]
    assert "alpha.lookup" not in await listed(harness, bob)
    response = await save(harness, mode="inherit", caps=[])
    assert response.status_code == 200
    assert response.json()["servers"]["alpha"]["effective_caps"] == ["read"]
    assert response.json()["user"]["denies"] == []
    assert "alpha.lookup" in await listed(harness, bob)
    assert "alpha.create_ticket" not in await listed(harness, bob)


async def test_manager_gets_actionable_visibility_error_without_a_partial_grant(harness):
    manager, headers = await person(harness, "manager")
    await person(harness, "bob")
    await private_server(harness)
    await harness.hub.redis.sadd(harness.hub.store.key("acl:managers"), manager.id)
    before = await harness.hub.redis.hget(harness.hub.store.key("acl:users"), "bob")
    response = await save(harness, headers=headers)
    assert response.status_code == 409 and "share" in response.json()["error"]
    assert before == await harness.hub.redis.hget(harness.hub.store.key("acl:users"), "bob")
    assert (await harness.hub.runtime.definition("alpha")).visibility == "private"
    assert (await save(harness, user="manager", headers=headers)).status_code == 403
    assert (await save(harness, user="alice", headers=headers)).status_code == 403
    # Once explicitly shared, a manager can change a regular person's capabilities.
    assert (await save(harness)).status_code == 200
    assert (await save(harness, headers=headers, caps=["read", "write"])).status_code == 200
    await harness.hub.redis.srem(harness.hub.store.key("acl:managers"), manager.id)
    with pytest.raises(HubError, match="role required"):
        await harness.hub.acl.set_server_access(manager, "bob", "alpha", "block", [])


@pytest.mark.parametrize(
    "payload",
    [
        {"mode": "grant", "caps": []},
        {"mode": "grant", "caps": ["root"]},
        {"mode": "unknown", "caps": ["read"]},
        {"mode": [], "caps": ["read"]},
    ],
)
async def test_invalid_access_does_not_change_either_visibility_or_permissions(harness, payload):
    await person(harness, "bob")
    await private_server(harness)
    response = await harness.client.put(
        "/admin/api/users/bob/access/alpha", json=payload, headers=harness.headers
    )
    assert response.status_code == 422
    assert (await harness.hub.runtime.definition("alpha")).visibility == "private"
    access = await harness.hub.acl.snapshot(Principal(id="bob", username="bob@example.test"))
    assert not access.user["grants"]


async def test_protected_and_missing_targets_do_not_create_inert_rules(harness):
    await person(harness, "bob")
    await private_server(harness)
    assert (await save(harness, user="alice", mode="block")).status_code == 409
    assert (await save(harness, user="missing")).status_code == 404
    assert (await save(harness, server="missing")).status_code == 404
    assert (await harness.hub.runtime.definition("alpha")).visibility == "private"


async def test_selected_people_limit_fails_without_saving_a_partial_rule(harness):
    await person(harness, "bob")
    existing = [f"existing-{i}" for i in range(100)]
    await private_server(harness, visibility="shared", shared_with=existing)
    response = await save(harness)
    assert response.status_code == 409 and "100" in response.json()["error"]
    definition = await harness.hub.runtime.definition("alpha")
    assert definition.shared_with == existing and definition.visibility == "shared"
    raw = await harness.hub.redis.hget(harness.hub.store.key("acl:users"), "bob")
    assert not json.loads(raw)["grants"]


async def test_owner_access_and_nonexistent_server_explanation_are_explicit(harness):
    await person(harness, "bob")
    definition = ServerDefinition(name="alpha", owner="bob")
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    assert (await save(harness, mode="block")).status_code == 409
    response = await harness.client.get("/admin/api/access?server=missing", headers=harness.headers)
    assert response.status_code == 404


async def test_simultaneous_grants_preserve_both_people_and_concurrent_server_state(harness):
    await person(harness, "bob")
    await person(harness, "carol")
    await private_server(harness)
    results = await asyncio.gather(
        save(harness, user="bob"),
        save(harness, user="carol", caps=["read", "write"]),
        harness.hub.store.patch_dynamic("alpha", {"status": "starting", "code_version": "new"}),
    )
    assert all(result.status_code == 200 for result in results[:2])
    definition = await harness.hub.runtime.definition("alpha")
    assert set(definition.shared_with) == {"bob", "carol"}
    assert definition.status == "starting" and definition.code_version == "new"
    for name in ("bob", "carol"):
        raw = await harness.hub.redis.hget(harness.hub.store.key("acl:users"), name)
        assert "alpha" in json.loads(raw)["grants"]


async def test_access_directory_includes_private_offline_servers_and_explains_automatic_access(
    harness,
):
    _, bob = await person(harness, "bob")
    await private_server(harness)
    await harness.hub.store.save_dynamic(
        "offline", ServerDefinition(name="offline", owner="bob").model_dump()
    )
    response = await harness.client.get("/admin/api/access?server=alpha", headers=harness.headers)
    assert response.status_code == 200
    data = response.json()
    assert {s["name"] for s in data["servers"]} == {"alpha", "offline"}
    assert data["members"]["alice"]["admin"] and data["members"]["alice"]["owner"]
    assert not data["members"]["bob"]["visible"]
    assert all(isinstance(u["denies"], list) for u in data["users"])
    assert (await harness.client.get("/admin/api/access", headers=bob)).status_code == 403
    personal = (
        await harness.client.get("/admin/api/users/bob/servers", headers=harness.headers)
    ).json()
    assert (
        personal["servers"]["offline"]["owner"] and not personal["servers"]["offline"]["available"]
    )


async def test_saving_credentials_and_their_preference_is_atomic_and_validated_first(harness):
    response = await harness.client.post(
        "/credentials",
        json={"service": "alpha", "credentials": {"api_key": "personal"}, "only_mine": True},
        headers=harness.headers,
    )
    assert response.status_code == 204
    assert (await harness.hub.credentials.modes("alice"))["alpha"]
    encrypted = await harness.hub.redis.get(harness.hub.store.key("creds:alice:alpha"))
    assert harness.hub.credentials.cipher.decrypt(encrypted)["api_key"] == "personal"
    response = await harness.client.post(
        "/credentials",
        json={"service": "alpha", "credentials": {"api_key": "changed"}, "only_mine": "false"},
        headers=harness.headers,
    )
    assert response.status_code == 422
    assert encrypted == await harness.hub.redis.get(harness.hub.store.key("creds:alice:alpha"))
