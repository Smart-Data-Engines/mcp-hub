import pytest

from mcp_hub.models import ServerDefinition
from mcp_hub.store import dumps


@pytest.mark.parametrize(
    "supplied", [{}, {"_hub_username": "forged"}, {"password": ""}, {"password": None}]
)
async def test_identity_or_empty_values_are_not_personal_credentials(harness, supplied):
    definition = ServerDefinition(name="alpha", owner="alice", policy="user_only")
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    result = (
        await harness.rpc(
            "tools/call",
            {"name": "alpha.lookup", "arguments": {"query": "x"}},
            {"X-Hub-Credentials": dumps({"alpha": supplied})},
        )
    ).json()["result"]
    assert result["isError"] and result["_meta"]["hub/error"] == "credentials_required"
    assert not harness.session.calls


async def test_legacy_empty_encrypted_record_does_not_enable_user_only_fallback(harness):
    definition = ServerDefinition(name="alpha", owner="alice", policy="user_only")
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    await harness.hub.redis.set(
        harness.hub.store.key("creds:alice:alpha"), harness.hub.credentials.cipher.encrypt({})
    )
    result = (
        await harness.rpc("tools/call", {"name": "alpha.lookup", "arguments": {"query": "x"}})
    ).json()["result"]
    assert result["isError"] and not harness.session.calls


async def test_all_declared_personal_fields_are_required_without_technical_fallback(harness):
    definition = ServerDefinition(
        name="alpha", owner="alice", policy="user_only", user_env_fields=["user", "password"]
    )
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    for credentials in (
        {"fake": "not-an-authentication"},
        {"user": "alice"},
        {"password": "private"},
    ):
        result = (
            await harness.rpc(
                "tools/call",
                {"name": "alpha.lookup", "arguments": {"query": "x"}},
                {"X-Hub-Credentials": dumps({"alpha": credentials})},
            )
        ).json()["result"]
        assert result["isError"] and not harness.session.calls


async def test_only_mine_does_not_silently_switch_to_forced_global_account(harness):
    definition = ServerDefinition(name="alpha", owner="alice", policy="global_only")
    await harness.hub.store.save_dynamic("alpha", definition.model_dump())
    await harness.hub.credentials.set_mode("alice", "alpha", True)
    result = (
        await harness.rpc("tools/call", {"name": "alpha.lookup", "arguments": {"query": "x"}})
    ).json()["result"]
    assert result["isError"] and not harness.session.calls


async def test_global_secret_rotation_keeps_running_snapshot_redaction(harness):
    old = "old-value-that-must-remain-private"
    await harness.hub.credentials.save_global_env("alpha", {"SERVICE_PASSWORD": old})
    await harness.hub.redis.set(
        harness.hub.store.key("mcp:running-env:alpha"),
        harness.hub.credentials.cipher.encrypt({"SERVICE_PASSWORD": old}),
    )
    await harness.hub.credentials.save_global_env(
        "alpha", {"SERVICE_PASSWORD": "new-value-not-deployed-yet"}
    )

    class Reply:
        alive = True

        async def call(self, *args):
            return {"content": [{"type": "text", "text": old}]}

        async def close(self):
            pass

    harness.hub.upstreams.sessions["alpha"] = Reply()
    response = await harness.rpc(
        "tools/call", {"name": "alpha.lookup", "arguments": {"query": "x"}}
    )
    assert old not in response.text
    assert (
        response.headers["x-request-id"]
        == response.json()["result"]["_meta"]["hub/provenance"]["request_id"]
    )
