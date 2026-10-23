import re
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mcp_hub.oauth import challenge


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


async def begin(harness, registration=None):
    client = (
        registration
        or (
            await harness.client.post(
                "/oauth/register",
                json={
                    "client_name": "Test client",
                    "redirect_uris": ["http://127.0.0.1:5555/callback"],
                },
            )
        ).json()
    )
    verifier = "v" * 64
    response = await harness.client.get(
        "/authorize",
        params={
            "client_id": client["client_id"],
            "redirect_uri": client["redirect_uris"][0],
            "response_type": "code",
            "code_challenge": challenge(verifier),
            "code_challenge_method": "S256",
            "state": "client-state",
        },
    )
    assert response.status_code == 302, response.text
    return client, verifier, parse_qs(urlsplit(response.headers["location"]).query)


def oidc_transport(key, settings, state, defect=""):
    public = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public.update(kid="key-1", use="sig", alg="RS256")

    def respond(request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": settings.idp_issuer
                    if defect != "discovery_issuer"
                    else "https://evil.test",
                    "authorization_endpoint": settings.idp_issuer + "/authorize",
                    "token_endpoint": settings.idp_issuer + "/token",
                    "jwks_uri": settings.idp_issuer + "/jwks",
                },
            )
        if request.url.path.endswith("/jwks"):
            return httpx.Response(200, json={"keys": [public]})
        if request.url.path.endswith("/token"):
            now = int(time.time())
            claims = {
                "iss": settings.idp_issuer,
                "aud": settings.idp_client_id,
                "sub": "employee-123",
                "iat": now,
                "exp": now + 300,
                "nonce": state["nonce"][0],
                "preferred_username": "employee@example.test",
                "email": "employee@example.test",
                "email_verified": True,
            }
            if settings.idp_provider == "google":
                claims["hd"] = "example.test"
            if defect == "nonce":
                claims["nonce"] = "forged"
            elif defect == "issuer":
                claims["iss"] = "https://evil.test"
            elif defect == "audience":
                claims["aud"] = "another-application"
            elif defect == "expired":
                claims["exp"] = now - 100
            elif defect == "domain":
                claims["email"] = "person@external.test"
            elif defect == "unverified_email":
                claims["email_verified"] = False
            elif defect == "azp":
                claims.update(aud=[settings.idp_client_id, "other"], azp="other")
            elif defect == "single_azp":
                claims["azp"] = "other"
            elif defect == "hosted_domain":
                claims["hd"] = "external.test"
            elif defect == "missing_hosted_domain":
                claims.pop("hd", None)
            elif defect == "username_admin":
                claims["preferred_username"] = "owner@example.test"
            token = jwt.encode(
                claims,
                key,
                algorithm="RS256",
                headers={"kid": "unknown" if defect == "kid" else "key-1"},
            )
            return httpx.Response(200, json={"id_token": token, "access_token": "not-a-hub-token"})
        return httpx.Response(404)

    return httpx.MockTransport(respond)


@pytest.mark.parametrize(
    "provider", ["google", "entra", "keycloak", "okta", "auth0", "gitlab", "oidc"]
)
async def test_all_provider_choices_use_verified_oidc_and_hub_tokens(
    harness, signing_key, provider
):
    settings = harness.hub.settings
    settings.idp_provider, settings.idp_issuer = provider, "https://identity.example.test"
    settings.idp_token_auth_method = (
        "client_secret_basic" if provider == "okta" else "client_secret_post"
    )
    settings.idp_client_id, settings.idp_client_secret = "hub-company-app", "company-secret"
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        registration, verifier, data = await begin(harness)
        state.update(data)
        response = await harness.client.get(
            f"/oauth/{provider}/callback",
            params={"state": data["state"][0], "code": "provider-code"},
        )
        assert response.status_code == 200, response.text
        consent = re.search(r'name="consent" value="([^"]+)"', response.text)[1]
        response = await harness.client.post(
            "/oauth/consent", data={"consent": consent, "decision": "allow"}
        )
        assert response.status_code == 302
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["state"] == ["client-state"]
        response = await harness.client.post(
            "/token",
            data={
                "client_id": registration["client_id"],
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "code_verifier": verifier,
                "redirect_uri": registration["redirect_uris"][0],
            },
        )
        assert response.status_code == 200
        token = response.json()["access_token"]
        assert token != "not-a-hub-token"
        principal = await harness.hub.oauth.validate_token(token)
        assert principal.username == "employee@example.test"
        access = await harness.hub.acl.snapshot(principal)
        assert access.user["group"] == "default" and not access.admin


@pytest.mark.parametrize(
    "defect",
    [
        "nonce",
        "issuer",
        "audience",
        "expired",
        "domain",
        "unverified_email",
        "azp",
        "single_azp",
        "kid",
    ],
)
async def test_invalid_idp_identity_never_provisions_or_issues_code(harness, signing_key, defect):
    settings = harness.hub.settings
    settings.idp_issuer, settings.idp_client_id, settings.idp_client_secret = (
        "https://identity.example.test",
        "hub-company-app",
        "company-secret",
    )
    settings.idp_allowed_domains = "example.test"
    state = {}
    async with httpx.AsyncClient(
        transport=oidc_transport(signing_key, settings, state, defect)
    ) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness)
        state.update(data)
        response = await harness.client.get(
            "/oauth/oidc/callback", params={"state": data["state"][0], "code": "provider-code"}
        )
        assert response.status_code in {401, 403}, response.text
        users = await harness.hub.redis.hgetall(harness.hub.store.key("acl:users"))
        assert len(users) == 1
        assert "not-a-hub-token" not in response.text


async def test_callback_is_browser_bound_and_replay_protected(harness, signing_key):
    settings = harness.hub.settings
    settings.idp_issuer, settings.idp_client_id, settings.idp_client_secret = (
        "https://identity.example.test",
        "hub-company-app",
        "company-secret",
    )
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness)
        state.update(data)
        cookies = dict(harness.client.cookies)
        harness.client.cookies.clear()
        params = {"state": data["state"][0], "code": "provider-code"}
        assert (await harness.client.get("/oauth/oidc/callback", params=params)).status_code == 400
        harness.client.cookies.update(cookies)
        assert (await harness.client.get("/oauth/oidc/callback", params=params)).status_code == 200
        assert (await harness.client.get("/oauth/oidc/callback", params=params)).status_code == 400


@pytest.mark.parametrize("defect", ["hosted_domain", "missing_hosted_domain"])
async def test_google_workspace_restriction_requires_the_verified_hosted_domain(
    harness, signing_key, defect
):
    settings = harness.hub.settings
    settings.idp_provider, settings.idp_issuer = "google", "https://identity.example.test"
    settings.idp_client_id, settings.idp_client_secret = "company", "secret"
    settings.idp_allowed_domains = "example.test"
    state = {}
    async with httpx.AsyncClient(
        transport=oidc_transport(signing_key, settings, state, defect)
    ) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness)
        state.update(data)
        response = await harness.client.get(
            "/oauth/google/callback", params={"state": data["state"][0], "code": "code"}
        )
        assert response.status_code == 403
        assert len(await harness.hub.redis.hgetall(harness.hub.store.key("acl:users"))) == 1


@pytest.mark.parametrize("spoof_username", [False, True])
async def test_operator_admin_policy_uses_verified_email_not_a_displayed_username(
    harness, signing_key, spoof_username
):
    settings = harness.hub.settings
    settings.idp_provider, settings.idp_issuer = "google", "https://identity.example.test"
    settings.idp_client_id, settings.idp_client_secret = "company", "secret"
    settings.idp_allowed_domains = "example.test"
    settings.admin_emails = "owner@example.test" if spoof_username else "employee@example.test"
    state = {}
    defect = "username_admin" if spoof_username else ""
    async with httpx.AsyncClient(
        transport=oidc_transport(signing_key, settings, state, defect)
    ) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness)
        state.update(data)
        response = await harness.client.get(
            "/oauth/google/callback", params={"state": data["state"][0], "code": "code"}
        )
        assert response.status_code == 200, response.text
    members = await harness.hub.redis.smembers(harness.hub.store.key("acl:admins"))
    assert len(members) == (0 if spoof_username else 1)
    assert "alice" not in members
    if not spoof_username:
        before = set(members)
        await harness.hub.acl.apply_admin_policy(settings.admin_emails)
        assert set(await harness.hub.redis.smembers(harness.hub.store.key("acl:admins"))) == before


async def test_operator_admin_policy_blocks_manual_role_changes(harness):
    harness.hub.settings.admin_emails = "alice@example.test"
    response = await harness.client.get("/admin/api/admins", headers=harness.headers)
    assert response.status_code == 200 and response.json()["managed"]
    for method in ("POST", "DELETE"):
        response = await harness.client.request(
            method, "/admin/api/admins/alice", headers=harness.headers
        )
        assert response.status_code == 403


async def test_verified_console_signin_returns_directly_with_pkce_and_ui_session(
    harness, signing_key
):
    settings = harness.hub.settings
    settings.idp_provider, settings.idp_issuer = "google", "https://accounts.google.com"
    settings.idp_client_id, settings.idp_client_secret = "company", "secret"
    settings.idp_allowed_domains = "example.test"
    settings.admin_emails = "employee@example.test"
    console = await harness.hub.store.get("oauth:client:mcp-hub-admin")
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        registration, verifier, data = await begin(harness, console)
        state.update(data)
        response = await harness.client.get(
            "/oauth/google/callback", params={"state": data["state"][0], "code": "code"}
        )
        assert response.status_code == 302, response.text
        target = urlsplit(response.headers["location"])
        assert target.path == "/admin/"
        result = parse_qs(target.query)
        assert result["state"] == ["client-state"]
        assert harness.client.cookies.get("hub_ui")
        assert not harness.client.cookies.get("hub_login")
        params = {
            "client_id": registration["client_id"],
            "grant_type": "authorization_code",
            "redirect_uri": registration["redirect_uris"][0],
            "code": result["code"][0],
            "code_verifier": "incorrect-verifier",
        }
        assert (await harness.client.post("/token", data=params)).status_code == 400
        params["code_verifier"] = verifier
        exchanged = await harness.client.post("/token", data=params)
        assert exchanged.status_code == 200, exchanged.text
        assert (await harness.client.post("/token", data=params)).status_code == 400
        principal = await harness.hub.oauth.validate_token(exchanged.json()["access_token"])
        assert principal.may_manage and principal.username == "employee@example.test"
        access = await harness.hub.acl.snapshot(principal)
        assert access.admin
        whoami = await harness.client.get(
            "/admin/api/whoami",
            headers={"Authorization": "Bearer " + exchanged.json()["access_token"]},
        )
        assert whoami.status_code == 200 and whoami.json()["interaction_csrf"]


async def test_console_callback_keeps_browser_binding_and_replay_protection(harness, signing_key):
    settings = harness.hub.settings
    settings.idp_issuer, settings.idp_client_id, settings.idp_client_secret = (
        "https://identity.example.test",
        "company",
        "secret",
    )
    console = await harness.hub.store.get("oauth:client:mcp-hub-admin")
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness, console)
        state.update(data)
        cookies = dict(harness.client.cookies)
        harness.client.cookies.clear()
        params = {"state": data["state"][0], "code": "code"}
        assert (await harness.client.get("/oauth/oidc/callback", params=params)).status_code == 400
        harness.client.cookies.update(cookies)
        assert (await harness.client.get("/oauth/oidc/callback", params=params)).status_code == 302
        assert (await harness.client.get("/oauth/oidc/callback", params=params)).status_code == 400


@pytest.mark.parametrize(
    "changed", ["redirect_uris", "management_allowed", "token_endpoint_auth_method"]
)
async def test_console_configuration_change_cannot_send_a_code_to_another_destination(
    harness, signing_key, changed
):
    settings = harness.hub.settings
    settings.idp_issuer, settings.idp_client_id, settings.idp_client_secret = (
        "https://identity.example.test",
        "company",
        "secret",
    )
    console = await harness.hub.store.get("oauth:client:mcp-hub-admin")
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness, console)
        state.update(data)
        console[changed] = {
            "redirect_uris": ["https://other.example.test/callback"],
            "management_allowed": False,
            "token_endpoint_auth_method": "client_secret_post",
        }[changed]
        await harness.hub.store.put("oauth:client:mcp-hub-admin", console)
        response = await harness.client.get(
            "/oauth/oidc/callback", params={"state": data["state"][0], "code": "code"}
        )
        assert response.status_code == 400
        assert "location" not in response.headers


async def test_external_client_cannot_skip_consent_by_copying_console_metadata(
    harness, signing_key
):
    settings = harness.hub.settings
    settings.idp_issuer, settings.idp_client_id, settings.idp_client_secret = (
        "https://identity.example.test",
        "company",
        "secret",
    )
    registration = (
        await harness.client.post(
            "/oauth/register",
            json={
                "client_id": "mcp-hub-admin",
                "client_name": "MCP Hub console",
                "trusted_first_party": True,
                "redirect_uris": [settings.hub_public_url + "/admin/"],
            },
        )
    ).json()
    assert registration["client_id"] != "mcp-hub-admin"
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        _, verifier, data = await begin(harness, registration)
        state.update(data)
        response = await harness.client.get(
            "/oauth/oidc/callback", params={"state": data["state"][0], "code": "code"}
        )
        assert response.status_code == 200 and "Allow access" in response.text
        consent = re.search(r'name="consent" value="([^"]+)"', response.text)[1]
        response = await harness.client.post(
            "/oauth/consent", data={"consent": consent, "decision": "allow"}
        )
        code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
        response = await harness.client.post(
            "/token",
            data={
                "client_id": registration["client_id"],
                "grant_type": "authorization_code",
                "redirect_uri": registration["redirect_uris"][0],
                "code_verifier": verifier,
                "code": code,
            },
        )
        assert response.status_code == 200
        principal = await harness.hub.oauth.validate_token(response.json()["access_token"])
        assert not principal.may_manage


async def test_external_consent_escapes_labels_and_denial_returns_to_client(harness, signing_key):
    settings = harness.hub.settings
    settings.idp_issuer, settings.idp_client_id, settings.idp_client_secret = (
        "https://identity.example.test",
        "company",
        "secret",
    )
    registration = (
        await harness.client.post(
            "/oauth/register",
            json={
                "client_name": '<script>alert("client")</script>',
                "redirect_uris": ["http://127.0.0.1:5555/callback?connection=desktop"],
            },
        )
    ).json()
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness, registration)
        state.update(data)
        response = await harness.client.get(
            "/oauth/oidc/callback", params={"state": data["state"][0], "code": "code"}
        )
        assert "<script>" not in response.text and "&lt;script&gt;" in response.text
        assert 'name="viewport"' in response.text and "<style>" in response.text
        assert (
            "form-action 'self' http://127.0.0.1:5555"
            in response.headers["content-security-policy"]
        )
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        consent = re.search(r'name="consent" value="([^"]+)"', response.text)[1]
        post = {"consent": consent, "decision": "deny"}
        response = await harness.client.post("/oauth/consent", data=post)
        assert response.status_code == 302
        params = parse_qs(urlsplit(response.headers["location"]).query)
        assert params == {
            "connection": ["desktop"],
            "error": ["access_denied"],
            "state": ["client-state"],
        }
        assert not harness.client.cookies.get("hub_login")
        response = await harness.client.post("/oauth/consent", data=post)
        assert response.status_code == 400 and "Open MCP Hub" in response.text
        ordinary = await harness.client.get("/health")
        assert "127.0.0.1:5555" not in ordinary.headers["content-security-policy"]


async def test_consent_from_another_browser_does_not_consume_the_request(harness, signing_key):
    settings = harness.hub.settings
    settings.idp_issuer, settings.idp_client_id, settings.idp_client_secret = (
        "https://identity.example.test",
        "company",
        "secret",
    )
    state = {}
    async with httpx.AsyncClient(transport=oidc_transport(signing_key, settings, state)) as client:
        harness.hub.oauth.http = client
        _, _, data = await begin(harness)
        state.update(data)
        response = await harness.client.get(
            "/oauth/oidc/callback", params={"state": data["state"][0], "code": "code"}
        )
        consent = re.search(r'name="consent" value="([^"]+)"', response.text)[1]
        cookies = dict(harness.client.cookies)
        harness.client.cookies.clear()
        post = {"consent": consent, "decision": "allow"}
        assert (await harness.client.post("/oauth/consent", data=post)).status_code == 400
        harness.client.cookies.update(cookies)
        assert (await harness.client.post("/oauth/consent", data=post)).status_code == 302


@pytest.mark.parametrize(
    "uri",
    [
        "https://client.test';form-action *;other/callback",
        "https://client.test:invalid/callback",
        "https://client.test:99999/callback",
    ],
)
async def test_invalid_redirect_cannot_inject_or_break_the_consent_security_policy(harness, uri):
    response = await harness.client.post("/oauth/register", json={"redirect_uris": [uri]})
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"
