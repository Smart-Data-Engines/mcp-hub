import asyncio

from mcp_hub.models import Principal
from mcp_hub.oauth import challenge


async def register(harness):
    response = await harness.client.post(
        "/oauth/register",
        json={
            "client_name": "test",
            "redirect_uris": ["http://127.0.0.1:1234/callback"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert response.status_code == 201
    return response.json()


async def code_form(harness):
    client = await register(harness)
    verifier = "v" * 64
    code = await harness.hub.oauth.code(
        harness.principal,
        {
            "client_id": client["client_id"],
            "redirect_uri": client["redirect_uris"][0],
            "code_challenge": challenge(verifier),
        },
    )
    return {
        "grant_type": "authorization_code",
        "client_id": client["client_id"],
        "redirect_uri": client["redirect_uris"][0],
        "code": code,
        "code_verifier": verifier,
    }


async def test_concurrent_code_exchange_is_single_use(harness):
    params = await code_form(harness)
    responses = await asyncio.gather(
        *(harness.client.post("/token", data=params) for _ in range(10))
    )
    assert sorted(response.status_code for response in responses) == [200] + [400] * 9
    assert all(
        response.json().get("error") == "invalid_grant"
        for response in responses
        if response.status_code == 400
    )


async def test_pkce_client_and_redirect_are_bound(harness):
    params = await code_form(harness)
    for field, value in (
        ("code_verifier", "x" * 64),
        ("redirect_uri", "http://127.0.0.1/other"),
        ("client_id", "absent"),
    ):
        response = await harness.client.post("/token", data={**params, field: value})
        assert response.status_code in {400, 401}
    assert (await harness.client.post("/token", data=params)).status_code == 200


async def test_refresh_rotation_and_revocation_cascade(harness):
    first = (await harness.client.post("/token", data=(params := await code_form(harness)))).json()
    refresh_form = {
        "grant_type": "refresh_token",
        "refresh_token": first["refresh_token"],
        "client_id": params["client_id"],
    }
    responses = await asyncio.gather(
        *(harness.client.post("/token", data=refresh_form) for _ in range(5))
    )
    good = [response for response in responses if response.status_code == 200]
    assert len(good) == 1
    second = good[0].json()
    assert await harness.hub.oauth.validate_token(first["access_token"]) is None
    assert await harness.hub.oauth.validate_token(second["access_token"])
    response = await harness.client.post(
        "/oauth/revoke", data={"client_id": params["client_id"], "token": second["refresh_token"]}
    )
    assert response.status_code == 200
    assert await harness.hub.oauth.validate_token(second["access_token"]) is None


async def test_principal_revocation_does_not_touch_bystanders_or_scan(harness, monkeypatch):
    alice = await harness.hub.oauth._issue(harness.principal, "a")
    bob = await harness.hub.oauth._issue(Principal(id="bob", username="bob"), "b")

    async def forbidden(*args, **kwargs):
        raise AssertionError("Token revocation must not scan keyspace")

    monkeypatch.setattr(harness.hub.redis, "scan", forbidden)
    monkeypatch.setattr(harness.hub.redis, "keys", forbidden)
    await harness.hub.oauth.revoke_principal("alice")
    assert await harness.hub.oauth.validate_token(alice["access_token"]) is None
    assert await harness.hub.oauth.validate_token(bob["access_token"])


async def test_bot_registration_requires_admin_and_bot_starts_empty(harness):
    response = await harness.client.post(
        "/oauth/register",
        json={
            "redirect_uris": ["https://example.test/callback"],
            "grant_types": ["client_credentials"],
        },
    )
    assert response.status_code == 400
    response = await harness.client.post(
        "/admin/api/clients", json={"client_name": "CI bot"}, headers=harness.headers
    )
    assert response.status_code == 201
    client = response.json()
    assert "client_secret" in client
    stored = await harness.hub.store.get("oauth:client:" + client["client_id"])
    assert client["client_secret"] not in str(stored)
    token = (
        await harness.client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client["client_id"],
                "client_secret": client["client_secret"],
            },
        )
    ).json()
    result = (
        await harness.rpc(
            "tools/list", headers={"Authorization": "Bearer " + token["access_token"]}
        )
    ).json()["result"]
    assert [tool["name"] for tool in result["tools"]] == ["hub.discover_tools"]


async def test_auth_rate_limit(harness):
    harness.hub.settings.auth_rate_limit = 10
    responses = [
        await harness.client.post("/token", data={"grant_type": "invalid"}) for _ in range(11)
    ]
    assert responses[-1].status_code == 429
    assert "retry-after" in responses[-1].headers
