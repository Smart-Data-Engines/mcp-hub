"""Abuse probes use small configurable budgets, not load against a shared deployment."""

import asyncio
import json
from dataclasses import fields
from types import SimpleNamespace

import pytest

from mcp_hub.models import ServerDefinition
from mcp_hub.oauth import OAuthError, challenge


def registration_budget(harness, monkeypatch, capacity=2):
    original = harness.hub.settings
    values = {field.name: getattr(original, field.name) for field in fields(original)}
    values.update(max_oauth_clients=capacity, oauth_registration_ttl=60, resource=original.resource)
    monkeypatch.setattr(harness.hub.oauth, "settings", SimpleNamespace(**values))
    return harness.hub.oauth


async def test_public_client_registration_has_an_atomic_storage_budget(harness, monkeypatch):
    oauth = registration_budget(harness, monkeypatch)
    payload = {"redirect_uris": ["http://127.0.0.1/callback"]}
    outcomes = await asyncio.gather(
        *(oauth.register_client(payload) for _ in range(3)), return_exceptions=True
    )
    assert sum(isinstance(result, OAuthError) for result in outcomes) == 1
    assert await harness.hub.redis.zcard(harness.hub.store.key("oauth:dynamic-clients")) == 2


async def test_unused_registration_expires_but_successful_exchange_extends_it(harness, monkeypatch):
    oauth = registration_budget(harness, monkeypatch)
    client = await oauth.register_client({"redirect_uris": ["http://127.0.0.1/callback"]})
    key = harness.hub.store.key("oauth:client:" + client["client_id"])
    assert 0 < await harness.hub.redis.ttl(key) <= 60
    verifier = "v" * 64
    code = await oauth.code(
        harness.principal,
        {
            "client_id": client["client_id"],
            "redirect_uri": client["redirect_uris"][0],
            "code_challenge": challenge(verifier),
        },
    )
    tokens = await oauth.exchange(
        {
            "client_id": client["client_id"],
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": client["redirect_uris"][0],
        }
    )
    assert await oauth.validate_token(tokens["access_token"])
    assert await harness.hub.redis.ttl(key) >= harness.hub.settings.refresh_token_ttl - 2


async def test_expired_client_cannot_race_code_exchange_into_new_tokens(harness, monkeypatch):
    from tests.integration.test_oauth import code_form

    form = await code_form(harness)
    original = harness.hub.oauth._issue

    async def expire_before_issue(*args, **kwargs):
        await harness.hub.store.delete("oauth:client:" + form["client_id"])
        return await original(*args, **kwargs)

    monkeypatch.setattr(harness.hub.oauth, "_issue", expire_before_issue)
    response = await harness.client.post("/token", data=form)
    assert response.status_code == 401 and response.json()["error"] == "invalid_client"
    assert "access_token" not in response.text


@pytest.mark.parametrize("oversized", ["arguments", "tool"])
async def test_large_request_cannot_expand_audit_storage_without_bound(harness, oversized):
    call = {"name": "alpha.lookup", "arguments": {"query": "small"}}
    if oversized == "arguments":
        call["arguments"]["query"] = "x" * 50000
    else:
        call["name"] = "x" * 50000 + ".lookup"
    response = await harness.rpc("tools/call", call)
    assert response.status_code == 200
    raw = await harness.hub.redis.lindex(harness.hub.store.key("audit:spool"), 0)
    assert len(raw.encode()) <= 8192
    value = json.loads(raw)
    assert value["request_id"] and value["status"] and value["principal_id"] == "alice"


async def test_approval_storage_rejects_arguments_too_large_to_review(harness):
    await harness.hub.store.save_dynamic(
        "alpha", ServerDefinition(name="alpha", owner="alice", approval_required=True).model_dump()
    )
    response = await harness.rpc(
        "tools/call", {"name": "alpha.delete_ticket", "arguments": {"query": "x" * 17000}}
    )
    assert response.json()["result"]["_meta"]["hub/error"] == "approval_too_large"
    assert await harness.hub.redis.zcard(harness.hub.store.key("approval:_index")) == 0
    assert not harness.session.calls


async def test_failed_catalog_validation_does_not_keep_old_tools_callable(harness):
    session = harness.session
    session.url = "http://synthetic-adapter/mcp"
    valid = False

    async def tools():
        properties = {"query": {"type": "string"}}
        if valid:
            properties["credentials"] = {"type": "object"}
        return [
            {
                "name": "lookup",
                "inputSchema": {"type": "object", "properties": properties},
                "annotations": {"readOnlyHint": True},
            }
        ]

    session.tools = tools
    await harness.hub.store.register(
        "alpha", {"name": "alpha", "url": session.url, "code_version": "abc123"}, 60
    )
    await harness.hub.upstreams.refresh()
    call = {"name": "alpha.lookup", "arguments": {"query": "same request"}}
    result = (await harness.rpc("tools/call", call)).json()["result"]
    assert result["isError"] and result["_meta"]["hub/error"] == "catalog_unavailable"
    assert not session.calls
    valid = True
    await harness.hub.upstreams.refresh()
    assert not (await harness.rpc("tools/call", call)).json()["result"]["isError"]
    assert len(session.calls) == 1


async def test_credential_mutations_share_a_principal_rate_limit(harness):
    harness.hub.settings.credential_write_rate_limit = 2
    first = await harness.client.post(
        "/credentials",
        headers=harness.headers,
        json={"service": "alpha", "credentials": {"token": "synthetic"}},
    )
    second = await harness.client.post(
        "/credentials/mode", headers=harness.headers, json={"service": "alpha", "only_mine": True}
    )
    third = await harness.client.delete("/credentials/alpha", headers=harness.headers)
    assert (first.status_code, second.status_code, third.status_code) == (204, 204, 429)
    assert "retry-after" in third.headers
    assert await harness.hub.credentials.services("alice") == ["alpha"]


async def test_server_owner_cannot_raise_the_deployment_call_ceiling(harness):
    await harness.hub.store.save_dynamic(
        "alpha", ServerDefinition(name="alpha", owner="alice").model_dump()
    )
    response = await harness.client.put(
        "/admin/api/servers-dynamic/alpha",
        headers=harness.headers,
        json={"call_timeout": harness.hub.settings.upstream_call_tool_timeout + 1},
    )
    assert response.status_code == 422
    assert (await harness.hub.store.dynamic())["alpha"]["call_timeout"] is None


async def test_registration_expiry_releases_capacity(harness, monkeypatch):
    oauth = registration_budget(harness, monkeypatch, capacity=1)
    old = await oauth.register_client({"redirect_uris": ["http://127.0.0.1/callback"]})
    await harness.hub.store.delete("oauth:client:" + old["client_id"])
    await harness.hub.redis.zadd(
        harness.hub.store.key("oauth:dynamic-clients"), {old["client_id"]: 0}
    )
    current = await oauth.register_client({"redirect_uris": ["http://127.0.0.1/callback"]})
    assert current["client_id"] != old["client_id"]
    assert await harness.hub.redis.zcard(harness.hub.store.key("oauth:dynamic-clients")) == 1


@pytest.mark.parametrize("service", ["_index", "modes"])
async def test_service_names_cannot_overwrite_or_delete_credential_bookkeeping(harness, service):
    credentials = harness.hub.credentials
    await credentials.save("alice", "ordinary", {"token": "kept"}, only_mine=True)
    # Deleting an absent connection must not touch its sibling index or preference hash.
    await credentials.delete("alice", service)
    assert await credentials.services("alice") == ["ordinary"]
    assert (await credentials.modes("alice"))["ordinary"]
    await credentials.save("alice", service, {"token": "special"})
    resolved = await credentials.resolve(harness.principal, service, "user_only", None)
    assert resolved.credentials["token"] == "special"
    await credentials.delete("alice", service)
    assert await credentials.services("alice") == ["ordinary"]
    assert (await credentials.modes("alice"))["ordinary"]


async def test_legacy_credential_format_remains_readable_after_update(harness):
    credentials, store = harness.hub.credentials, harness.hub.store
    legacy = store.key("creds:alice:legacy")
    await harness.hub.redis.set(legacy, credentials.cipher.encrypt({"token": "old"}))
    await harness.hub.redis.sadd(store.key("creds:alice:_index"), "legacy")
    assert (await credentials.resolve(harness.principal, "legacy", "user_only", None)).credentials[
        "token"
    ] == "old"
    await credentials.save("alice", "legacy", {"token": "new"})
    assert credentials.cipher.decrypt(await harness.hub.redis.get(legacy)) == {"token": "new"}
    assert (await credentials.resolve(harness.principal, "legacy", "user_only", None)).credentials[
        "token"
    ] == "new"


async def test_legacy_server_timeout_cannot_escape_the_global_deadline(harness):
    harness.hub.settings.upstream_call_tool_timeout = 0.05
    harness.hub.settings.session_read_timeout = 0.02
    await harness.hub.store.save_dynamic(
        "alpha", ServerDefinition(name="alpha", owner="alice", call_timeout=10).model_dump()
    )

    async def slow(*args):
        await asyncio.sleep(0.2)
        return {"content": [{"type": "text", "text": "late"}]}

    harness.session.call = slow
    result = (
        await harness.rpc(
            "tools/call", {"name": "alpha.lookup", "arguments": {"query": "deadline"}}
        )
    ).json()["result"]
    assert result["isError"] and result["_meta"]["hub/error"] == "timeout"
