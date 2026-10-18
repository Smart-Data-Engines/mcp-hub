"""Executable invariants from product specification §14.3 (100 examples each)."""

import asyncio
import time
from unittest.mock import patch

import fakeredis.aioredis
import httpx
import pytest
from cryptography.fernet import Fernet
from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_hub.acl import ACL, Access
from mcp_hub.config import Settings
from mcp_hub.credentials import Credentials
from mcp_hub.gateway import Gateway, RequestContext
from mcp_hub.models import ALL_CAPS, NAME, HubError, Principal, visible
from mcp_hub.oauth import OAuth, challenge, verify_pkce
from mcp_hub.observability import Audit, Metrics
from mcp_hub.security import Cipher, cap_text, category, public_schema, scrub
from mcp_hub.store import Store, dumps
from mcp_hub.upstreams import Circuit, Upstreams

settings.register_profile("invariants", max_examples=100, deadline=None)
settings.load_profile("invariants")
names = st.sets(st.sampled_from(["alpha", "bravo", "charlie", "delta", "echo"]), max_size=5)
masks = st.sets(st.sampled_from(sorted(ALL_CAPS)))
verifiers = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
    min_size=43,
    max_size=128,
)
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=60),
    lambda child: (
        st.lists(child, max_size=5) | st.dictionaries(st.text(max_size=20), child, max_size=5)
    ),
    max_leaves=15,
)


def config():
    return Settings(
        store_url="redis://:test@localhost:6379",
        credentials_encryption_key=Fernet.generate_key().decode(),
        environment="development",
    )


async def core():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store = Store(redis)
    acl = ACL(store)
    await acl.initialize()
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(503)))
    conf = config()
    return redis, store, acl, OAuth(store, conf, acl, http), http, conf


@given(verifiers)
def test_pkce_round_trip_and_different_verifier(verifier):
    assert verify_pkce(verifier, challenge(verifier))
    assert not verify_pkce(verifier + "x", challenge(verifier))


@given(st.dictionaries(st.text(max_size=15), json_values, max_size=8))
def test_authenticated_encryption_round_trip(value):
    cipher = Cipher(Fernet.generate_key().decode())
    assert cipher.decrypt(cipher.encrypt(value)) == value


@given(names, names, names)
def test_personal_grant_overrides_deny(group, grant, deny):
    access = Access(
        Principal(id="u", username="u"),
        {"grants": {name: ["read"] for name in grant}, "denies": list(deny)},
        {"servers": {name: ["read"] for name in group}},
        {},
        False,
        False,
    )
    assert {name for name in group | grant | deny if access.permits(name, "read")} == (
        group - deny
    ) | grant


@given(names, names, names, st.sampled_from(["alpha", "bravo", "charlie", "delta", "echo"]))
def test_missing_effective_server_denies_call(group, grant, deny, name):
    access = Access(
        Principal(id="u", username="u"),
        {"grants": {s: ["read"] for s in grant}, "denies": list(deny)},
        {"servers": {s: ["read"] for s in group}},
        {},
        False,
        False,
    )
    if name not in (group - deny) | grant:
        assert not any(access.permits(name, category) for category in ALL_CAPS)


@given(masks, masks, st.sampled_from(sorted(ALL_CAPS)))
def test_capability_masks_are_unions(group, grant, kind):
    access = Access(
        Principal(id="u", username="u"),
        {"grants": {"s": sorted(grant)}, "denies": []},
        {"servers": {"s": sorted(group)}},
        {},
        False,
        False,
    )
    assert access.permits("s", kind) == (kind in group | grant)


@given(st.text(max_size=80), st.booleans(), st.booleans())
def test_annotations_always_override_name_heuristics(name, read_only, destructive):
    expected = "read" if read_only else "destructive" if destructive else "write"
    assert category(
        {"name": name, "annotations": {"readOnlyHint": read_only, "destructiveHint": destructive}}
    ) == (expected, True)


@given(st.sampled_from(["private", "shared", "public"]), st.booleans(), st.booleans())
def test_visibility_is_independent_of_acl(kind, owns, shared):
    principal = Principal(id="u", username="u")
    definition = {
        "owner": "u" if owns else "other",
        "visibility": kind,
        "shared_with": ["u"] if shared else [],
    }
    assert visible(definition, principal) == (
        owns or kind == "public" or (kind == "shared" and shared)
    )


@given(st.text(max_size=100))
def test_server_name_validation_accepts_only_contract_alphabet(name):
    expected = 1 <= len(name) <= 64 and all(
        c in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in name
    )
    assert bool(NAME.fullmatch(name)) == expected


@given(st.text(min_size=12, max_size=35), st.text(max_size=100))
def test_known_secret_does_not_survive_redaction(secret, text):
    if secret == "[REDACTED]":
        return
    output = scrub({"body": text + secret + text, "password": secret}, (secret,))
    assert secret not in dumps(output)
    assert output["password"] == "[REDACTED]"


@given(st.text(max_size=3000), st.integers(min_value=128, max_value=1024))
def test_cap_never_exceeds_limit_and_explains_truncation(text, limit):
    output = cap_text(text, limit)
    assert len(output) <= limit
    if len(text) > limit:
        assert "TRUNCATED" in output and str(len(text)) in output


@given(st.dictionaries(st.text(min_size=1, max_size=10), json_values, max_size=5))
def test_reserved_fields_are_removed_from_schema(arguments):
    properties = {**{key: {} for key in arguments}, "credentials": {}, "_hub_username": {}}
    schema = public_schema(
        {"type": "object", "properties": properties, "required": list(properties)}
    )
    assert "credentials" not in schema["properties"]
    assert "_hub_username" not in schema["required"]
    assert schema["additionalProperties"] is False


@given(st.integers(min_value=1, max_value=15), st.integers(min_value=1, max_value=35))
async def test_atomic_rate_never_allows_more_than_limit(limit, attempts):
    redis, store, _, _, http, _ = await core()
    results = await asyncio.gather(*(store.rate("x", limit, 60) for _ in range(attempts)))
    assert sum(allowed for allowed, _ in results) == min(limit, attempts)
    await redis.aclose()
    await http.aclose()


@given(verifiers)
async def test_code_is_single_use_even_when_exchanged_concurrently(verifier):
    redis, store, _, oauth, http, _ = await core()
    await store.put(
        "oauth:client:c",
        {
            "client_id": "c",
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "none",
        },
    )
    code = await oauth.code(
        Principal(id="u", username="u"),
        {
            "client_id": "c",
            "redirect_uri": "http://localhost/cb",
            "code_challenge": challenge(verifier),
        },
    )
    params = {
        "grant_type": "authorization_code",
        "client_id": "c",
        "redirect_uri": "http://localhost/cb",
        "code_verifier": verifier,
        "code": code,
    }
    results = await asyncio.gather(
        oauth.exchange(params), oauth.exchange(params), return_exceptions=True
    )
    assert sum(isinstance(value, dict) for value in results) == 1
    assert sum(isinstance(value, HubError) for value in results) == 1
    await redis.aclose()
    await http.aclose()


@given(verifiers, st.sampled_from(["code_verifier", "client_id", "redirect_uri"]))
async def test_code_rejects_each_mismatched_binding(verifier, field):
    redis, store, _, oauth, http, _ = await core()
    client = {"grant_types": ["authorization_code"], "token_endpoint_auth_method": "none"}
    await store.put("oauth:client:c", client)
    await store.put("oauth:client:other", client)
    code = await oauth.code(
        Principal(id="u", username="u"),
        {
            "client_id": "c",
            "redirect_uri": "http://localhost/cb",
            "code_challenge": challenge(verifier),
        },
    )
    params = {
        "grant_type": "authorization_code",
        "client_id": "c",
        "redirect_uri": "http://localhost/cb",
        "code_verifier": verifier,
        "code": code,
    }
    params[field] = {
        "code_verifier": verifier + "x",
        "client_id": "other",
        "redirect_uri": "http://localhost/different",
    }[field]
    with pytest.raises(HubError):
        await oauth.exchange(params)
    await redis.aclose()
    await http.aclose()


@given(st.text(alphabet="abcxyz", min_size=1, max_size=20))
async def test_refresh_rotation_invalidates_old_token(username):
    redis, store, _, oauth, http, _ = await core()
    await store.put(
        "oauth:client:c", {"grant_types": ["refresh_token"], "token_endpoint_auth_method": "none"}
    )
    first = await oauth._issue(Principal(id=username, username=username), "c")
    params = {
        "grant_type": "refresh_token",
        "client_id": "c",
        "refresh_token": first["refresh_token"],
    }
    second = await oauth.exchange(params)
    with pytest.raises(HubError):
        await oauth.exchange(params)
    assert await oauth.validate_token(first["access_token"]) is None
    assert await oauth.validate_token(second["access_token"])
    await redis.aclose()
    await http.aclose()


@given(st.integers(min_value=1, max_value=4), st.integers(min_value=1, max_value=4))
async def test_principal_revocation_preserves_all_bystander_tokens(own, other):
    redis, _, _, oauth, http, _ = await core()
    first = [await oauth._issue(Principal(id="a", username="a"), "c" + str(i)) for i in range(own)]
    second = [
        await oauth._issue(Principal(id="b", username="b"), "c" + str(i)) for i in range(other)
    ]
    await oauth.revoke_principal("a")
    assert all(
        value is None
        for value in await asyncio.gather(
            *(oauth.validate_token(token["access_token"]) for token in first)
        )
    )
    assert all(
        await asyncio.gather(*(oauth.validate_token(token["access_token"]) for token in second))
    )
    await redis.aclose()
    await http.aclose()


@given(
    st.lists(
        st.tuples(st.sampled_from(["create", "delete"]), st.sampled_from(["a", "b", "c", "d"])),
        max_size=20,
    )
)
async def test_dynamic_indexes_remain_consistent_after_arbitrary_operations(operations):
    redis, store, _, _, http, _ = await core()
    expected = set()
    for operation, name in operations:
        if operation == "create":
            value = await store.save_dynamic(
                name, {"name": name, "owner": "u", "visibility": "private"}, create=True
            )
            if name in expected:
                assert value == -1
            else:
                assert value == 1
                expected.add(name)
        else:
            await store.delete_dynamic(name)
            expected.discard(name)
    assert set(await store.dynamic()) == expected
    assert set(await redis.hgetall(store.key("acl:visibility"))) == expected
    await redis.aclose()
    await http.aclose()


@given(st.integers(min_value=1, max_value=5), st.integers(min_value=0, max_value=100))
def test_open_circuit_blocks_until_one_successful_probe(threshold, extra):
    circuit = Circuit(threshold, 5)
    for _ in range(threshold):
        circuit.failure()
    assert circuit.opened
    assert not any(circuit.allow() for _ in range(extra + 1))
    circuit.open_until = time.monotonic() - 1
    assert circuit.allow()
    assert not circuit.allow()
    circuit.success()
    assert circuit.allow() and not circuit.opened


@given(names, names, names, masks)
def test_shared_catalog_filter_equals_per_upstream_filter(group, grant, deny, mask):
    all_servers = {"alpha", "bravo", "charlie", "delta", "echo"}
    access = Access(
        Principal(id="u", username="u"),
        {"grants": {name: sorted(mask) for name in grant}, "denies": list(deny)},
        {"servers": {name: sorted(mask) for name in group}},
        {},
        False,
        False,
    )
    catalog = [(server, kind) for server in sorted(all_servers) for kind in sorted(ALL_CAPS)]
    filtered = {(server, kind) for server, kind in catalog if access.permits(server, kind)}
    independent = {(server, kind) for server in (group - deny) | grant for kind in mask}
    assert filtered == independent


@given(names, names)
async def test_registry_expiration_and_reconciliation_converge(registered, expired):
    redis, store, _, _, http, conf = await core()

    class Session:
        alive = True

        def __init__(self, url, secret, settings):
            self.url = url

        async def connect(self):
            pass

        async def close(self):
            self.alive = False

        async def tools(self):
            return [
                {
                    "name": "read",
                    "inputSchema": {"type": "object", "properties": {"credentials": {}}},
                    "annotations": {"readOnlyHint": True},
                }
            ]

    upstreams = Upstreams(store, conf, Metrics())
    for name in registered:
        await store.register(name, {"name": name, "url": "http://" + name + "/mcp"}, 60)
    for name in expired:
        await redis.delete(store.key("mcp:registered:" + name))
    with patch("mcp_hub.upstreams.Session", Session):
        await upstreams.refresh()
    expected = registered - expired
    assert set(upstreams.sessions) == expected
    assert set((await store.catalog())["servers"]) == expected
    await upstreams.close()
    await redis.aclose()
    await http.aclose()


async def gateway_core():
    redis, store, acl, _, http, conf = await core()
    principal = Principal(id="u", username="real-caller")
    await acl.provision(principal)
    await redis.sadd(store.key("acl:admins"), principal.id)
    metrics = Metrics()
    creds = Credentials(store, Cipher(conf.credentials_encryption_key))
    upstreams = Upstreams(store, conf, metrics)
    gateway = Gateway(
        store, conf, acl, creds, upstreams, Audit(store, conf, metrics, http), metrics
    )
    schema = public_schema(
        {"type": "object", "properties": {"query": {"type": "string"}, "credentials": {}}}
    )
    await store.publish_catalog(
        {
            "a": {
                "tools": [
                    {
                        "name": "write",
                        "inputSchema": schema,
                        "category": "write",
                        "accepts_credentials": True,
                    }
                ],
                "status": "connected",
                "policy": "both",
            }
        }
    )
    return redis, http, gateway, RequestContext(principal)


@given(st.text(max_size=30), st.text(max_size=30))
async def test_client_arguments_never_supply_upstream_identity(spoofed, password):
    redis, http, gateway, ctx = await gateway_core()

    class Session:
        alive = True

        async def call(self, name, arguments, budget, request_id):
            assert arguments["credentials"] == {
                "_hub_username": "real-caller",
                "_hub_user_id": "u",
                "_hub_principal": "human",
            }
            assert "_hub_username" not in arguments
            return {"content": [{"type": "text", "text": "ok"}]}

    gateway.upstreams.sessions["a"] = Session()
    result = await gateway.call(
        "a.write",
        {
            "query": "x",
            "credentials": {"password": password, "_hub_username": spoofed},
            "_hub_username": spoofed,
        },
        ctx,
    )
    assert not result.get("isError")
    await redis.aclose()
    await http.aclose()


@given(st.text(max_size=50))
async def test_duplicate_writes_invoke_upstream_once(query):
    redis, http, gateway, ctx = await gateway_core()
    calls = []

    class Session:
        alive = True

        async def call(self, name, arguments, budget, request_id):
            calls.append(arguments)
            await asyncio.sleep(0)
            return {"content": [{"type": "text", "text": "created"}]}

    gateway.upstreams.sessions["a"] = Session()
    await asyncio.gather(
        gateway.call("a.write", {"query": query}, ctx),
        gateway.call("a.write", {"query": query}, RequestContext(ctx.principal)),
    )
    assert len(calls) == 1
    await redis.aclose()
    await http.aclose()


@given(st.booleans(), st.text(max_size=30))
async def test_shutdown_finishes_or_explicitly_reports_interruption(cancel, query):
    redis, http, gateway, ctx = await gateway_core()
    started, release = asyncio.Event(), asyncio.Event()

    class Session:
        alive = True

        async def call(self, name, arguments, budget, request_id):
            started.set()
            await release.wait()
            return {"content": [{"type": "text", "text": "finished"}]}

    gateway.upstreams.sessions["a"] = Session()
    task = asyncio.create_task(gateway.call("a.write", {"query": query}, ctx))
    await started.wait()
    gateway.draining = True
    if cancel:
        task.cancel()
    else:
        release.set()
    result = await task
    assert "shutting down" in dumps(result) if cancel else "finished" in dumps(result)
    assert await redis.llen(gateway.store.key("audit:spool")) == 1
    await redis.aclose()
    await http.aclose()
