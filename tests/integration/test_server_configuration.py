import asyncio

import pytest

from mcp_hub.models import ServerDefinition

BASE = "/admin/api/servers-dynamic/alpha"


async def configured_server(harness):
    await harness.hub.store.save_dynamic(
        "alpha", ServerDefinition(name="alpha", owner="alice", status="running").model_dump()
    )
    await harness.hub.registry.commit(
        "alice/alpha",
        {"env.yaml": "env: [API_TOKEN, WORKSPACE]\nuser_env: [personal_key]\n"},
        "Declare connection fields",
    )
    values = {"API_TOKEN": "private-original-token", "WORKSPACE": "original-workspace"}
    await harness.hub.credentials.save_global_env("alpha", values)
    await harness.hub.redis.set(
        harness.hub.store.key("mcp:running-env:alpha"),
        harness.hub.credentials.cipher.encrypt(values),
    )


async def test_field_update_preserves_other_secrets_and_marks_restart_without_returning_values(
    harness,
):
    await configured_server(harness)
    response = await harness.client.patch(
        BASE + "/env", json={"values": {"WORKSPACE": "new-workspace"}}, headers=harness.headers
    )
    assert response.status_code == 204
    values = await harness.hub.credentials.global_env("alpha")
    assert values == {"API_TOKEN": "private-original-token", "WORKSPACE": "new-workspace"}
    raw = await harness.hub.redis.get(harness.hub.store.key("mcp:env:alpha"))
    assert "private-original-token" not in raw and "new-workspace" not in raw
    status = await harness.client.get(BASE + "/env", headers=harness.headers)
    assert status.json()["restart_required"] is True
    assert status.json()["configured"] == ["API_TOKEN", "WORKSPACE"]
    assert "private-original-token" not in status.text and "new-workspace" not in status.text
    assert (await harness.hub.credentials.global_env("alpha", running=True))[
        "WORKSPACE"
    ] == "original-workspace"


async def test_empty_patch_preserves_saved_fields_and_removal_is_explicit(harness):
    await configured_server(harness)
    response = await harness.client.patch(
        BASE + "/env", json={"values": {}}, headers=harness.headers
    )
    assert response.status_code == 204
    assert len(await harness.hub.credentials.global_env("alpha")) == 2
    response = await harness.client.patch(
        BASE + "/env", json={"values": {}, "remove": ["API_TOKEN"]}, headers=harness.headers
    )
    assert response.status_code == 204
    assert await harness.hub.credentials.global_env("alpha") == {"WORKSPACE": "original-workspace"}


async def test_unused_legacy_values_do_not_show_a_permanent_restart_notice(harness):
    await configured_server(harness)
    values = await harness.hub.credentials.global_env("alpha")
    await harness.hub.credentials.save_global_env("alpha", {**values, "LEGACY_FIELD": "unused"})
    response = await harness.client.get(BASE + "/env", headers=harness.headers)
    assert response.status_code == 200
    assert response.json()["restart_required"] is False


@pytest.mark.parametrize(
    "data",
    [
        {"values": {"API_TOKEN": ""}},
        {"values": {"API_TOKEN": "  "}},
        {"values": {"UNDECLARED": "value"}},
        {"values": {}, "remove": ["UNDECLARED"]},
        {"values": {}, "remove": [None]},
        {"values": {"API_TOKEN": "new"}, "remove": ["API_TOKEN"]},
    ],
)
async def test_invalid_changes_cannot_erase_existing_values(harness, data):
    await configured_server(harness)
    before = await harness.hub.credentials.global_env("alpha")
    response = await harness.client.patch(BASE + "/env", json=data, headers=harness.headers)
    assert response.status_code == 422
    assert await harness.hub.credentials.global_env("alpha") == before


async def test_owner_without_admin_role_cannot_update_or_inspect_saved_global_values(harness):
    await configured_server(harness)
    await harness.hub.redis.srem(harness.hub.store.key("acl:admins"), "alice")
    response = await harness.client.patch(
        BASE + "/env", json={"values": {}, "remove": ["API_TOKEN"]}, headers=harness.headers
    )
    assert response.status_code == 403
    metadata = (await harness.client.get(BASE + "/env", headers=harness.headers)).json()
    assert not metadata["configuration_visible"] and metadata["configured"] == []
    assert (
        await harness.client.get(BASE + "/env/values", headers=harness.headers)
    ).status_code == 403
    assert len(await harness.hub.credentials.global_env("alpha")) == 2


async def test_concurrent_field_changes_do_not_overwrite_each_other(harness, monkeypatch):
    await configured_server(harness)
    redis = harness.hub.redis
    original_get = redis.get
    barrier, reads = asyncio.Barrier(2), 0

    async def simultaneous_read(key):
        nonlocal reads
        result = await original_get(key)
        if key == harness.hub.store.key("mcp:env:alpha") and reads < 2:
            reads += 1
            await barrier.wait()
        return result

    monkeypatch.setattr(redis, "get", simultaneous_read)
    await asyncio.gather(
        harness.hub.credentials.patch_global_env("alpha", {"API_TOKEN": "rotated-token"}, []),
        harness.hub.credentials.patch_global_env(
            "alpha", {"WORKSPACE": "concurrent-workspace"}, []
        ),
    )
    assert await harness.hub.credentials.global_env("alpha") == {
        "API_TOKEN": "rotated-token",
        "WORKSPACE": "concurrent-workspace",
    }


async def test_source_information_does_not_fetch_code_or_expose_git_credentials(
    harness, monkeypatch
):
    await configured_server(harness)
    harness.hub.settings.registry_backend = "git"
    harness.hub.settings.registry_git_remote = (
        "https://private-user:secret-token@bitbucket.org/team/registry.git?token=hidden#secret"
    )

    async def forbidden(*args):
        raise AssertionError("Opening the Source tab must not download the source snapshot")

    monkeypatch.setattr(harness.hub.registry, "snapshot", forbidden)
    response = await harness.client.get(BASE + "/source", headers=harness.headers)
    assert response.status_code == 200
    info = response.json()
    assert info["repository"] == "bitbucket.org/team/registry"
    assert info["folder"] == "alice/alpha"
    assert info["folder_url"].endswith("/src/main/alice/alpha")
    assert all(
        secret not in response.text
        for secret in ["private-user", "secret-token", "hidden", "#secret"]
    )
