import ast
import asyncio
import io
import json
import zipfile

import httpx
import pytest

from mcp_hub import starters
from mcp_hub.models import HubError, Principal, ServerDefinition
from mcp_hub.starter_code.v1 import github_client

BASE = "/admin/api/servers-dynamic/github-example"
TOKEN = "synthetic-personal-token"
VALUES = {"token": TOKEN, "repository": "sample/project"}


async def create(harness, monkeypatch, starter="github", name="github-example"):
    monkeypatch.setattr(harness.hub.runtime, "_require", lambda: object())
    response = await harness.client.post(
        "/admin/api/servers-dynamic",
        json={"name": name, "starter_id": starter},
        headers=harness.headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


async def test_starters_create_read_and_delete_without_any_registry_access(harness, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Bundled starters must not access the customer's registry")

    monkeypatch.setattr(harness.hub.registry, "snapshot", forbidden)
    monkeypatch.setattr(harness.hub.registry, "commit", forbidden)
    harness.hub.settings.registry_read_only = True
    catalog = await harness.client.get("/admin/api/starters", headers=harness.headers)
    assert [s["id"] for s in catalog.json()["starters"]] == ["demo", "github", "notion"]
    for starter in ["demo", "github", "notion"]:
        name = starter + "-included"
        definition = await create(harness, monkeypatch, starter, name)
        assert definition["starter_version"] == "1.0.0"
        assert definition["policy"] == ("global_only" if starter == "demo" else "user_only")
        base = "/admin/api/servers-dynamic/" + name
        info = (await harness.client.get(base + "/source", headers=harness.headers)).json()
        assert info["kind"] == "starter" and not info["editing_enabled"]
        files = (await harness.client.get(base + "/files", headers=harness.headers)).json()
        assert len(files["commit"]) == 40 and "serve(mcp)" in files["files"]["server.py"]
        download = await harness.client.get(base + "/starter-source", headers=harness.headers)
        assert download.status_code == 200 and download.headers["content-type"].startswith(
            "application/zip"
        )
        with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
            assert sorted(archive.namelist()) == sorted(files["files"])
            assert all(
                archive.read(name).decode() == value for name, value in files["files"].items()
            )
        assert (await harness.client.get(base + "/env", headers=harness.headers)).status_code == 200
        for method, suffix, data in [
            ("POST", "/files", {"files": {"server.py": "bad"}}),
            ("DELETE", "/files/server.py", None),
        ]:
            response = await harness.client.request(
                method, base + suffix, json=data, headers=harness.headers
            )
            assert response.status_code == 403
        assert (
            await harness.client.put(base, json={"pinned_ref": "main"}, headers=harness.headers)
        ).status_code == 422
        response = await harness.client.put(
            base, json={"memory_mb": 768, "cpus": 0.5}, headers=harness.headers
        )
        assert response.status_code == 200
        changed = await harness.hub.runtime.snapshot(await harness.hub.runtime.definition(name))
        assert "768m" in changed.files["docker.yaml"]

        async def stopped(server_name):
            value = await harness.hub.runtime.definition(server_name)
            value.status = "stopped"
            return value

        monkeypatch.setattr(harness.hub.runtime, "stop", stopped)
        assert (await harness.client.delete(base, headers=harness.headers)).status_code == 204
        assert name not in await harness.hub.store.dynamic()


async def test_unknown_starter_and_source_metadata_cannot_be_injected(harness, monkeypatch):
    monkeypatch.setattr(harness.hub.runtime, "_require", lambda: object())
    for values in [
        {"starter_id": "../private"},
        {"starter_id": "github", "starter_version": "9"},
        {"starter_id": "github", "owner": "other"},
    ]:
        if "owner" in values:
            await harness.hub.redis.srem(harness.hub.store.key("acl:admins"), "alice")
        response = await harness.client.post(
            "/admin/api/servers-dynamic",
            json={"name": "rejected", **values},
            headers=harness.headers,
        )
        assert response.status_code in {403, 422}
    assert "rejected" not in await harness.hub.store.dynamic()


async def test_personal_connection_is_encrypted_hidden_and_blank_preserves_token(
    harness, monkeypatch
):
    await create(harness, monkeypatch)
    response = await harness.client.patch(
        BASE + "/starter-connection", json={"values": VALUES}, headers=harness.headers
    )
    assert response.status_code == 204
    response = await harness.client.get(BASE + "/starter-connection", headers=harness.headers)
    info = response.json()
    assert info["personal"]["repository"] == "sample/project"
    assert info["personal"]["configured"] == ["token", "repository"]
    assert TOKEN not in response.text
    encrypted = await harness.hub.redis.get(harness.hub.store.key("creds:alice:github-example"))
    assert TOKEN not in encrypted and "sample/project" not in encrypted
    response = await harness.client.patch(
        BASE + "/starter-connection",
        json={"values": {"token": "", "repository": "sample/second"}},
        headers=harness.headers,
    )
    assert response.status_code == 204
    assert await harness.hub.credentials.personal("alice", "github-example") == {
        "token": TOKEN,
        "repository": "sample/second",
    }
    await harness.hub.credentials.set_mode("alice", "github-example", True)
    assert (
        await harness.client.delete(BASE + "/starter-connection", headers=harness.headers)
    ).status_code == 204
    assert await harness.hub.credentials.personal("alice", "github-example") == {}
    assert (await harness.hub.credentials.modes("alice"))["github-example"] is True


async def test_github_test_uses_all_four_read_checks_and_rejects_missing_permissions(
    harness, monkeypatch
):
    await create(harness, monkeypatch)
    await harness.client.patch(
        BASE + "/starter-connection", json={"values": VALUES}, headers=harness.headers
    )
    requests = []

    def provider(request):
        requests.append(request)
        assert request.method == "GET" and request.url.host == "api.github.com"
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        if request.url.path == "/user":
            return httpx.Response(200, json={"login": "sample-user"})
        if request.url.path.endswith(("/issues", "/pulls")):
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"full_name": "sample/project", "private": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
        monkeypatch.setattr(harness.hub, "http", client)
        response = await harness.client.post(
            BASE + "/starter-connection/test", json={}, headers=harness.headers
        )
    assert response.status_code == 200, response.text
    assert response.json()["connection"] == "personal" and len(requests) == 4
    assert TOKEN not in response.text

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(403, json={"message": TOKEN}))
    ) as client:
        monkeypatch.setattr(harness.hub, "http", client)
        response = await harness.client.post(
            BASE + "/starter-connection/test", json={}, headers=harness.headers
        )
    assert response.status_code == 422 and TOKEN not in response.text
    assert "read permissions" in response.json()["error"]


@pytest.mark.parametrize(
    "values",
    [
        {"token": TOKEN},
        {"repository": "sample/project"},
        {**VALUES, "repository": "https://internal.example/private"},
        {**VALUES, "repository": "../private"},
        {**VALUES, "token": "a\r\nX-Foo: value"},
        {**VALUES, "url": "http://localhost"},
        {"token": [], "repository": "sample/project"},
    ],
)
async def test_invalid_connection_cannot_replace_saved_values(harness, monkeypatch, values):
    await create(harness, monkeypatch)
    # Partial first-time setup is refused; partial later updates preserve saved fields.
    response = await harness.client.patch(
        BASE + "/starter-connection", json={"values": values}, headers=harness.headers
    )
    assert response.status_code == 422
    assert not await harness.hub.credentials.personal("alice", "github-example")


async def test_shared_connection_admin_boundary_and_only_personal_preference(harness, monkeypatch):
    await create(harness, monkeypatch)
    response = await harness.client.patch(
        BASE + "/starter-connection",
        json={"policy": "global_only", "values": VALUES},
        headers=harness.headers,
    )
    assert response.status_code == 204
    assert (await harness.hub.runtime.definition("github-example")).policy == "global_only"
    assert await harness.hub.credentials.global_env("github-example") == {
        "GITHUB_TOKEN": TOKEN,
        "GITHUB_REPOSITORY": "sample/project",
    }
    await harness.hub.credentials.set_mode("alice", "github-example", True)
    response = await harness.client.post(
        BASE + "/starter-connection/test", json={}, headers=harness.headers
    )
    assert response.status_code == 403 and "personal" in response.json()["error"]
    await harness.hub.redis.srem(harness.hub.store.key("acl:admins"), "alice")
    for method in ["PATCH", "DELETE"]:
        response = await harness.client.request(
            method,
            BASE + "/starter-connection",
            json={"policy": "global_only", "values": VALUES} if method == "PATCH" else None,
            headers=harness.headers,
        )
        assert response.status_code == 403
    info = (await harness.client.get(BASE + "/starter-connection", headers=harness.headers)).json()
    assert info["shared"] == {"configured": [], "repository": ""}


async def test_people_cannot_read_or_use_another_persons_connection(harness, monkeypatch):
    await create(harness, monkeypatch)
    await harness.client.patch(
        BASE + "/starter-connection", json={"values": VALUES}, headers=harness.headers
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
    definition = await harness.hub.runtime.definition("github-example")
    definition.visibility = "shared"
    definition.shared_with = ["bob"]
    await harness.hub.runtime.save(definition, fields={"visibility", "shared_with"})
    key = harness.hub.store.key("acl:users")
    user = json.loads(await harness.hub.redis.hget(key, "bob"))
    user["grants"]["github-example"] = ["read"]
    await harness.hub.redis.hset(key, "bob", json.dumps(user))
    info = await harness.client.get(BASE + "/starter-connection", headers=headers)
    assert info.status_code == 200 and info.json()["personal"]["configured"] == []
    assert TOKEN not in info.text
    response = await harness.client.post(
        BASE + "/starter-connection/test", json={}, headers=headers
    )
    assert response.status_code == 403 and "credentials" in response.json()["error"].lower()


async def test_atomic_personal_patch_preserves_concurrent_token_and_repository_changes(
    harness, monkeypatch
):
    await create(harness, monkeypatch)
    await harness.client.patch(
        BASE + "/starter-connection", json={"values": VALUES}, headers=harness.headers
    )
    original_get = harness.hub.redis.get
    barrier, count = asyncio.Barrier(2), 0

    async def get(key):
        nonlocal count
        result = await original_get(key)
        if key == harness.hub.store.key("creds:alice:github-example") and count < 2:
            count += 1
            await barrier.wait()
        return result

    monkeypatch.setattr(harness.hub.redis, "get", get)
    responses = await asyncio.gather(
        *[
            harness.client.patch(
                BASE + "/starter-connection", json={"values": values}, headers=harness.headers
            )
            for values in [{"token": "changed-personal-token"}, {"repository": "sample/concurrent"}]
        ]
    )
    assert all(r.status_code == 204 for r in responses)
    assert await harness.hub.credentials.personal("alice", "github-example") == {
        "token": "changed-personal-token",
        "repository": "sample/concurrent",
    }


async def test_provider_redirects_and_oversized_responses_are_not_followed_or_parsed():
    calls = []

    def redirect(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/private"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(redirect)) as client:
        with pytest.raises(HubError):
            await github_client.get(client, TOKEN, "sample/project")
    assert len(calls) == 1 and calls[0].url.host == "api.github.com"
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=b"x" * (github_client.MAX_RESPONSE + 1))
        )
    ) as client:
        with pytest.raises(HubError) as error:
            await github_client.get(client, TOKEN, "sample/project")
    assert error.value.status == 413


def test_starter_versions_are_pinned_and_contain_complete_public_source():
    d = ServerDefinition(
        name="example", owner="alice", starter_id="github", starter_version="1.0.0"
    )
    a, b = starters.snapshot(d), starters.snapshot(d)
    assert a == b and "async def get_repository" in a.files["server.py"]
    module = ast.parse(a.files["github_client.py"])
    api = next(
        node.value
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "API" for target in node.targets)
    )
    assert isinstance(api, ast.Constant) and api.value == "https://api.github.com"
    assert "credentials" in a.files["server.py"]
    d.starter_version = "not-shipped"
    with pytest.raises(HubError, match="not available"):
        starters.snapshot(d)
