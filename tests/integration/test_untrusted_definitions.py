"""An independent HTTP producer must not execute schemas inside the controller."""

import os
from contextlib import AsyncExitStack

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp_hub.models import HubError, Principal, ServerDefinition
from mcp_hub.registry import LocalGitRegistry, Snapshot
from mcp_hub.runtime import resource_limits
from mcp_hub.upstream import RequireHubSecret
from mcp_hub.upstreams import Session
from tests.integration.test_live_protocol import cluster, sdk_client, serving


class RawProducer:
    def __init__(self, schema, value):
        self.schema, self.value, self.effects = schema, value, 0
        self.app = Starlette(routes=[Route("/mcp", self.handle, methods=["POST", "GET", "DELETE"])])

    async def handle(self, request):
        if request.method != "POST":
            return Response(status_code=405)
        data = await request.json()
        if "id" not in data:
            return Response(status_code=202)
        method = data["method"]
        if method == "initialize":
            result = {
                "protocolVersion": data["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "synthetic-untrusted", "version": "1"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "lookup",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"credentials": {"type": "object"}},
                        },
                        "outputSchema": self.schema,
                    }
                ]
            }
        elif method == "tools/call":
            self.effects += 1
            result = {
                "content": [{"type": "text", "text": "synthetic-result"}],
                "structuredContent": self.value,
                "isError": False,
            }
        else:
            result = {}
        return JSONResponse({"jsonrpc": "2.0", "id": data["id"], "result": result})


live = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("MCP_HUB_RUN_LIVE") != "1",
        reason="Real loopback MCP producer requires MCP_HUB_RUN_LIVE=1",
    ),
]


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": {"value": {"type": "string", "pattern": "["}}},
        {"type": "object", "$ref": "#"},
        {"type": "object", "$ref": "https://must-not-fetch.invalid/schema"},
    ],
    ids=["invalid-regex", "recursive-ref", "remote-ref"],
)
@live[0]
@live[1]
async def test_adapter_output_schema_is_not_executed_by_the_hub(settings, schema):
    producer = RawProducer(schema, {"value": "synthetic"})
    async with serving(RequireHubSecret(producer.app, "test-secret")) as (url, _):
        session = Session(url + "/mcp", "test-secret", settings)
        try:
            await session.connect()
            assert len(await session.tools()) == 1
            result = await session.call("lookup", {}, 2, "schema-boundary")
            assert result["structuredContent"] == {"value": "synthetic"}
            assert producer.effects == 1
        finally:
            await session.close()


@live[0]
@live[1]
async def test_upstream_structured_content_is_still_subject_to_json_limits(settings):
    value = {}
    for _ in range(70):
        value = {"nested": value}
    producer = RawProducer({"type": "object"}, value)
    async with serving(RequireHubSecret(producer.app, "test-secret")) as (url, _):
        session = Session(url + "/mcp", "test-secret", settings)
        try:
            await session.connect()
            await session.tools()
            with pytest.raises(HubError, match="JSON"):
                await session.call("lookup", {}, 2, "bounded-output")
        finally:
            await session.close()


@live[0]
@live[1]
async def test_read_only_client_cannot_dispatch_an_unannotated_effect(settings):
    producer = RawProducer({"type": "object"}, {"effect": "synthetic"})
    async with cluster(settings) as c, AsyncExitStack() as stack:
        url, _ = await stack.enter_async_context(
            serving(RequireHubSecret(producer.app, settings.hub_upstream_secret))
        )
        response = await c["http"].post(
            "/register",
            json={"name": "unannotated", "url": url + "/mcp", "code_version": "one"},
            headers={"x-hub-secret": settings.hub_registration_secret},
        )
        assert response.status_code == 201
        await c["hub"].upstreams.refresh()
        reader = Principal(id="read-only", username="reader@example.test")
        await c["hub"].acl.provision(reader)
        for name in ("a", "unannotated"):
            await c["hub"].acl.change_user(reader.id, "grant", {"server": name, "caps": ["read"]})
        token = (await c["hub"].oauth._issue(reader, "read-client"))["access_token"]
        client = await sdk_client(stack, c["url"], token)
        control = await client.call_tool("a.lookup", {"query": "allowed read"})
        denied = await client.call_tool("unannotated.lookup", {})
        assert not control.isError
        assert denied.isError and producer.effects == 0
        assert "unannotated.lookup" not in {tool.name for tool in (await client.list_tools()).tools}


@pytest.mark.parametrize(
    "document",
    [
        "memory: &size 512m\ncpus: 1\nother: *size\n",
        "memory: 512m\nextra: " + "[" * 20 + "0" + "]" * 20,
        "memory: 512m\nextra: [" + ",".join("item" for _ in range(600)) + "]",
        "memory: 512m\n#" + "x" * 65536,
    ],
    ids=["alias", "depth", "nodes", "bytes"],
)
def test_controller_yaml_is_bounded_before_construction(document):
    with pytest.raises(HubError):
        resource_limits(document)
    assert resource_limits("memory: 512m\ncpus: 1\n") == (512, 1.0)


async def test_an_adapter_owner_cannot_feed_yaml_aliases_to_the_controller(harness):
    await harness.hub.store.save_dynamic(
        "alpha", ServerDefinition(name="alpha", owner="alice").model_dump()
    )
    await harness.hub.redis.srem(harness.hub.store.key("acl:admins"), "alice")

    class Registry:
        async def snapshot(self, folder, ref=""):
            return Snapshot(
                "a" * 40, {"env.yaml": "env: &fields [SERVICE_TOKEN]\nuser_env: *fields\n"}
            )

    harness.hub.registry = Registry()
    response = await harness.client.get(
        "/admin/api/servers-dynamic/alpha/env", headers=harness.headers
    )
    assert response.status_code == 422


@pytest.mark.parametrize("count,size", [(101, 1), (100, 200000)])
def test_git_snapshot_limits_are_checked_before_loading_blobs(tmp_path, monkeypatch, count, size):
    registry = LocalGitRegistry(str(tmp_path / "registry.git"))
    monkeypatch.setattr(registry, "_initialize", lambda: None)
    blobs = []

    def git(*arguments, **kwargs):
        if arguments[0] == "rev-parse":
            return b"a" * 40
        if arguments[0] == "ls-tree":
            return b"\0".join(
                b"100644 blob " + b"b" * 40 + b"\towner/demo/file" + str(i).encode()
                for i in range(count)
            )
        if arguments[:2] == ("cat-file", "-s"):
            return str(size).encode()
        assert arguments[:2] == ("cat-file", "blob")
        blobs.append(arguments)
        return b"x" * size

    monkeypatch.setattr(registry, "_git", git)
    with pytest.raises(HubError):
        registry._snapshot("owner/demo", "main")
    assert not blobs
