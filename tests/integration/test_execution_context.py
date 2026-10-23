"""Security regressions at actual authorization/credential/approval boundaries."""

import asyncio

import pytest

from mcp_hub.models import HubError, Principal, ServerDefinition
from mcp_hub.security import category
from mcp_hub.store import dumps
from tests.integration.test_concurrency_approvals import interactive


@pytest.mark.parametrize("name", ["lookup", "execute_sql", "insert", "get_and_delete"])
def test_unannotated_tool_is_never_assumed_read_only(name):
    assert category({"name": name}) == ("destructive", False)


async def test_stale_catalog_cannot_turn_an_unannotated_tool_into_a_read(harness):
    hub = harness.hub
    await hub.redis.srem(hub.store.key("acl:admins"), "alice")
    await hub.acl.change_user("alice", "grant", {"server": "alpha", "caps": ["read"]})
    catalog = (await hub.store.catalog())["servers"]
    tool = catalog["alpha"]["tools"][0]
    tool.update(annotations=None, annotated=False, category="read")
    await hub.store.publish_catalog(catalog)
    result = (
        await harness.rpc(
            "tools/call", {"name": "alpha.lookup", "arguments": {"query": "synthetic effect"}}
        )
    ).json()["result"]
    assert result["isError"] and result["_meta"]["hub/error"] == "blocked_acl"
    assert not harness.session.calls
    listing = (await harness.rpc("tools/list")).json()["result"]["tools"]
    assert "alpha.lookup" not in {item["name"] for item in listing}
    tool.update(annotations={"readOnlyHint": True}, annotated=True)
    await hub.store.publish_catalog(catalog)
    assert not (
        await harness.rpc(
            "tools/call", {"name": "alpha.lookup", "arguments": {"query": "safe read"}}
        )
    ).json()["result"]["isError"]
    assert len(harness.session.calls) == 1


async def approve(harness, identifier):
    headers = {**harness.headers, **await interactive(harness, "alice", "review-browser")}
    response = await harness.client.post(
        "/admin/api/approvals/" + identifier, json={"decision": "approve"}, headers=headers
    )
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("change", ["header", "saved", "global", "revision", "schema", "client"])
async def test_destructive_approval_cannot_follow_a_changed_execution_context(harness, change):
    hub = harness.hub
    definition = ServerDefinition(
        name="alpha", owner="alice", visibility="public", approval_required=True
    )
    await hub.store.save_dynamic("alpha", definition.model_dump())
    await hub.credentials.save("alice", "alpha", {"token": "synthetic-private-account-a"})
    await hub.credentials.save_global_env("alpha", {"SERVICE_TOKEN": "synthetic-global-a"})
    call = {"name": "alpha.delete_ticket", "arguments": {"query": "one"}}
    first = (await harness.rpc("tools/call", call)).json()["result"]
    assert first["_meta"]["hub/error"] == "blocked_approval"
    old = (await harness.client.get("/admin/api/approvals", headers=harness.headers)).json()[
        "approvals"
    ][0]
    assert "execution_context" not in old
    await approve(harness, old["id"])
    headers = {}
    if change == "header":
        headers["X-Hub-Credentials"] = dumps({"alpha": {"token": "synthetic-private-account-b"}})
    elif change == "saved":
        await hub.credentials.save("alice", "alpha", {"token": "synthetic-private-account-b"})
    elif change == "global":
        await hub.credentials.save_global_env("alpha", {"SERVICE_TOKEN": "synthetic-global-b"})
    elif change in {"revision", "schema"}:
        catalog = (await hub.store.catalog())["servers"]
        if change == "revision":
            catalog["alpha"]["code_version"] = "next-revision"
        else:
            catalog["alpha"]["tools"][2]["inputSchema"]["properties"]["query"]["maxLength"] = 100
        await hub.store.publish_catalog(catalog)
    else:
        token = (await hub.oauth._issue(harness.principal, "another-client", management=False))[
            "access_token"
        ]
        headers["Authorization"] = "Bearer " + token
    result = (await harness.rpc("tools/call", call, headers)).json()["result"]
    assert result["isError"] and result["_meta"]["hub/error"] == "blocked_approval"
    assert not harness.session.calls
    pending = [
        p
        for p in (await harness.client.get("/admin/api/approvals", headers=harness.headers)).json()[
            "approvals"
        ]
        if p["status"] == "pending"
    ]
    assert len(pending) == 1 and pending[0]["id"] != old["id"]
    await approve(harness, pending[0]["id"])
    assert not (await harness.rpc("tools/call", call, headers)).json()["result"]["isError"]
    assert len(harness.session.calls) == 1
    rows = await hub.redis.mget(
        [hub.store.key("approval:" + old["id"]), hub.store.key("approval:" + pending[0]["id"])]
    )
    assert all(
        "synthetic-private-account" not in row and "synthetic-global-" not in row for row in rows
    )


async def test_cached_write_still_enforces_current_personal_credential_policy(harness):
    await harness.hub.store.save_dynamic(
        "alpha", ServerDefinition(name="alpha", owner="alice").model_dump()
    )
    call = {"name": "alpha.create_ticket", "arguments": {"query": "same write"}}
    assert not (await harness.rpc("tools/call", call)).json()["result"]["isError"]
    await harness.hub.credentials.set_mode("alice", "alpha", True)
    result = (await harness.rpc("tools/call", call)).json()["result"]
    assert result["isError"] and result["_meta"]["hub/error"] == "credentials_required"
    assert len(harness.session.calls) == 1


async def test_cached_write_cannot_be_replayed_for_a_different_connection(harness):
    call = {"name": "alpha.create_ticket", "arguments": {"query": "same write"}}
    await harness.hub.credentials.save("alice", "alpha", {"token": "synthetic-account-a"})
    assert not (await harness.rpc("tools/call", call)).json()["result"]["isError"]
    await harness.hub.credentials.save("alice", "alpha", {"token": "synthetic-account-b"})
    result = (await harness.rpc("tools/call", call)).json()["result"]
    assert result["isError"] and result["_meta"]["hub/error"] == "idempotency_context_changed"
    assert len(harness.session.calls) == 1


@pytest.mark.parametrize("email", ["renamed@example.test", ""])
async def test_admin_policy_removes_the_subjects_previous_verified_email_binding(harness, email):
    policy = "alice@example.test,backup@example.test"
    backup = Principal(id="backup", username="backup@example.test")
    await harness.hub.acl.provision(backup)
    await harness.hub.acl.apply_admin_policy(
        policy, principal=backup, verified_email=backup.username
    )
    await harness.hub.acl.apply_admin_policy(
        policy, principal=harness.principal, verified_email="alice@example.test"
    )
    assert (await harness.hub.acl.snapshot(harness.principal)).admin
    await harness.hub.acl.apply_admin_policy(
        policy, principal=harness.principal, verified_email=email
    )
    assert not (await harness.hub.acl.snapshot(harness.principal)).admin
    assert (await harness.hub.acl.snapshot(backup)).admin


async def test_credential_document_size_is_bounded_before_persistence(harness):
    response = await harness.client.post(
        "/credentials",
        headers=harness.headers,
        json={"service": "alpha", "credentials": {"token": "x" * 16385}},
    )
    assert response.status_code == 413
    assert not await harness.hub.credentials.services("alice")


async def test_concurrent_credential_creation_cannot_overfill_the_principal_budget(harness):
    credentials = harness.hub.credentials
    for index in range(31):
        await credentials.save("alice", "service_" + str(index), {"token": "synthetic"})
    results = await asyncio.gather(
        *(credentials.save("alice", name, {"token": "synthetic"}) for name in ("last_a", "last_b")),
        return_exceptions=True,
    )
    assert sum(isinstance(result, HubError) for result in results) == 1
    assert len(await credentials.services("alice")) == 32
    await credentials.save("alice", "service_0", {"token": "updated"})
    await credentials.delete("alice", "service_1")
    await credentials.save("alice", "replacement", {"token": "synthetic"})
    assert len(await credentials.services("alice")) == 32


async def test_preference_budget_can_be_reclaimed_without_credential_fallback(harness):
    credentials = harness.hub.credentials
    for index in range(64):
        await credentials.set_mode("alice", "service_" + str(index), True)
    with pytest.raises(HubError):
        await credentials.set_mode("alice", "overflow", True)
    await credentials.set_mode("alice", "service_0", False)
    await credentials.set_mode("alice", "replacement", True)
    await credentials.save("alice", "replacement", {"token": "synthetic"})
    await credentials.delete("alice", "replacement")
    assert (await credentials.modes("alice"))["replacement"]
