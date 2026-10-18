"""Independent producer/consumer: actual TCP servers and the official MCP client."""

import asyncio
import json
import os
import socket
import time
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import replace

import fakeredis
import fakeredis.aioredis
import httpx
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from mcp_hub.app import create_app
from mcp_hub.cli import Server
from mcp_hub.models import Principal
from mcp_hub.upstream import RequireHubSecret

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("MCP_HUB_RUN_LIVE") != "1",
        reason="Set MCP_HUB_RUN_LIVE=1 for actual TCP MCP tests",
    ),
]


@asynccontextmanager
async def serving(app):
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    sock.setblocking(False)
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = Server(uvicorn.Config(app, log_level="error", access_log=False, log_config=None))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        for _ in range(200):
            if task.done():
                await task
                raise AssertionError("Server exited during startup")
            if server.started:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("ASGI server did not start")
        yield url, server
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=10)
        sock.close()


class CountRequests:
    def __init__(self, app):
        self.app, self.listings = app, 0

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks = []
        while True:
            message = await receive()
            chunks.append(message)
            if not message.get("more_body"):
                break
        try:
            parsed = json.loads(b"".join(message.get("body", b"") for message in chunks))
            self.listings += parsed.get("method") == "tools/list"
        except (ValueError, AttributeError):
            pass

        async def replay():
            if chunks:
                return chunks.pop(0)
            return await receive()

        await self.app(scope, replay, send)


def upstream(secret):
    mcp = FastMCP(
        "acceptance",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def lookup(query: str, credentials: dict | None = None) -> dict:
        return {
            "query": query,
            "caller": (credentials or {}).get("_hub_username"),
            "password": "upstream-secret-output",
        }

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def slow(delay: float, credentials: dict | None = None) -> str:
        await asyncio.sleep(delay)
        return "finished"

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
    async def large(size: int, credentials: dict | None = None) -> str:
        return "x" * size + " password=must-not-leak"

    return CountRequests(RequireHubSecret(mcp.streamable_http_app(), secret))


@asynccontextmanager
async def cluster(settings):
    conf = replace(
        settings,
        upstream_list_tools_timeout=0.5,
        session_read_timeout=0.35,
        upstream_call_tool_timeout=1.5,
        circuit_breaker_threshold=2,
        circuit_breaker_base_backoff=0.05,
    )
    fake_server = fakeredis.FakeServer()
    redis = fakeredis.aioredis.FakeRedis(server=fake_server, decode_responses=True)
    app = create_app(conf, redis=redis, background=False)
    hub = app.state.hub
    a, b = upstream(conf.hub_upstream_secret), upstream(conf.hub_upstream_secret)
    async with AsyncExitStack() as stack:
        a_url, a_server = await stack.enter_async_context(serving(a))
        b_url, b_server = await stack.enter_async_context(serving(b))
        hub_url, _ = await stack.enter_async_context(serving(app))
        http = await stack.enter_async_context(httpx.AsyncClient(base_url=hub_url, timeout=5))
        principal = Principal(id="acceptance", username="acceptance@example.test")
        await hub.acl.provision(principal)
        await redis.sadd(hub.store.key("acl:admins"), principal.id)
        token = (await hub.oauth._issue(principal, "acceptance-client"))["access_token"]
        for name, url in (("a", a_url), ("b", b_url)):
            response = await http.post(
                "/register",
                json={"name": name, "url": url + "/mcp", "code_version": "version-1"},
                headers={"x-hub-secret": conf.hub_registration_secret},
            )
            assert response.status_code == 201, response.text
        await hub.upstreams.refresh()
        yield {
            "app": app,
            "hub": hub,
            "http": http,
            "url": hub_url,
            "token": token,
            "a": a,
            "b": b,
            "a_url": a_url,
            "b_url": b_url,
            "b_server": b_server,
            "redis_server": fake_server,
            "settings": conf,
            "stack": stack,
        }
    await redis.aclose()


async def sdk_client(stack, url, token):
    http = await stack.enter_async_context(
        httpx.AsyncClient(
            headers={"Authorization": "Bearer " + token}, timeout=httpx.Timeout(30, read=300)
        )
    )
    read, write, _ = await stack.enter_async_context(
        streamable_http_client(url + "/mcp", http_client=http)
    )
    client = await stack.enter_async_context(ClientSession(read, write))
    await client.initialize()
    return client


async def test_catalog_has_zero_upstream_io_heartbeat_reuses_session_and_replica_restores(settings):
    async with cluster(settings) as c, AsyncExitStack() as clients:
        client = await sdk_client(clients, c["url"], c["token"])
        before = (c["a"].listings, c["b"].listings)
        tools = (await client.list_tools()).tools
        assert {tool.name for tool in tools} == {
            "a.lookup",
            "a.slow",
            "a.large",
            "b.lookup",
            "b.slow",
            "b.large",
            "hub.discover_tools",
        }
        for _ in range(20):
            await client.list_tools()
        assert (c["a"].listings, c["b"].listings) == before
        assert "credentials" not in json.dumps([tool.model_dump() for tool in tools])
        session = c["hub"].upstreams.sessions["a"]
        calling = asyncio.create_task(client.call_tool("a.slow", {"delay": 0.15}))
        await asyncio.sleep(0.03)
        for _ in range(2):
            response = await c["http"].post(
                "/register",
                json={"name": "a", "url": c["a_url"] + "/mcp", "code_version": "version-1"},
                headers={"x-hub-secret": settings.hub_registration_secret},
            )
            assert response.status_code == 409
            assert c["hub"].upstreams.sessions["a"] is session
        assert not (await calling).isError
        redis2 = fakeredis.aioredis.FakeRedis(server=c["redis_server"], decode_responses=True)
        app2 = create_app(c["settings"], redis=redis2, background=False)
        second_url, _ = await c["stack"].enter_async_context(serving(app2))
        assert (await c["http"].get(second_url + "/ready")).status_code == 200
        assert set(app2.state.hub.upstreams.sessions) == {"a", "b"}
        client2 = await sdk_client(clients, second_url, c["token"])
        assert {tool.name for tool in (await client2.list_tools()).tools} == {
            tool.name for tool in tools
        }
        await c["http"].post(
            "/unregister",
            json={"name": "b"},
            headers={"x-hub-secret": settings.hub_registration_secret},
        )
        await app2.state.hub.upstreams.refresh()
        assert set(app2.state.hub.upstreams.sessions) == {"a"}
        await redis2.aclose()


async def test_timeout_preserves_session_and_open_circuit_fails_fast(settings):
    async with cluster(settings) as c, AsyncExitStack() as clients:
        client = await sdk_client(clients, c["url"], c["token"])
        session = c["hub"].upstreams.sessions["a"]
        result = await client.call_tool("a.slow", {"delay": 0.7})
        assert result.isError and "time budget" in str(result)
        assert c["hub"].upstreams.sessions["a"] is session
        assert c["hub"].upstreams.circuit("a").failures == 0
        assert not (await client.call_tool("a.lookup", {"query": "ok"})).isError
        c["b_server"].should_exit = True
        await asyncio.sleep(0.25)
        await c["hub"].upstreams.refresh()
        assert (await c["hub"].store.catalog())["servers"]["b"]["status"] == "degraded"
        assert "b.lookup" in {tool.name for tool in (await client.list_tools()).tools}
        await c["hub"].upstreams.refresh()
        assert c["hub"].upstreams.circuit("b").opened
        started = time.monotonic()
        result = await client.call_tool("b.lookup", {"query": "offline"})
        assert result.isError and "circuit" in str(result)
        assert time.monotonic() - started < 0.2
        assert not (await client.call_tool("a.lookup", {"query": "still healthy"})).isError


async def test_full_transport_redaction_cap_and_upstream_authentication(settings):
    async with cluster(settings) as c:
        response = await c["http"].post(c["a_url"] + "/mcp", json={})
        assert response.status_code == 401
        async with AsyncExitStack() as clients:
            client = await sdk_client(clients, c["url"], c["token"])
            result = await client.call_tool(
                "a.lookup", {"query": "q", "credentials": {"_hub_username": "forged"}}
            )
            text = str(result)
            assert (
                "acceptance@example.test" in text
                and "forged" not in text
                and "upstream-secret-output" not in text
            )
            c["hub"].settings.max_response_chars = 1024
            result = await client.call_tool("a.large", {"size": 5000})
            assert "TRUNCATED" in str(result) and "must-not-leak" not in str(result)
