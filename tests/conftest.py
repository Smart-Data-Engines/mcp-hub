from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import fakeredis.aioredis
import httpx
import pytest
from cryptography.fernet import Fernet

from mcp_hub.app import create_app
from mcp_hub.config import Settings
from mcp_hub.models import Principal
from mcp_hub.security import public_schema
from mcp_hub.store import dumps


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        store_url="redis://:test-password@localhost:6379/0",
        credentials_encryption_key=Fernet.generate_key().decode(),
        environment="development",
        hub_registration_secret="registration-test-secret",
        hub_upstream_secret="upstream-test-secret",
        registry_backend="local",
        registry_local_path=str(tmp_path / "registry.git"),
        server_source_dir=str(tmp_path / "servers"),
        auth_rate_limit=10000,
    )


class FakeSession:
    alive = True

    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail: Exception | None = None

    async def call(self, name, arguments, budget, request_id):
        self.calls.append((name, arguments))
        if self.fail:
            raise self.fail
        return {
            "content": [
                {
                    "type": "text",
                    "text": dumps(
                        {
                            "greeting": "hello",
                            "caller": arguments.get("credentials", {}).get("_hub_username"),
                            "password": "very-private-password",
                            "query": arguments.get("query"),
                        }
                    ),
                }
            ],
            "isError": False,
        }

    async def close(self):
        self.alive = False


@dataclass
class Harness:
    app: Any
    client: httpx.AsyncClient
    headers: dict[str, str]
    principal: Principal
    session: FakeSession

    @property
    def hub(self):
        return self.app.state.hub

    async def rpc(self, method: str, params=None, headers=None):
        return await self.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
            headers={
                **self.headers,
                "Accept": "application/json, text/event-stream",
                **(headers or {}),
            },
        )


@pytest.fixture
async def harness(settings):
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(503))
    ) as upstream_http:
        app = create_app(settings, redis=redis, http_client=upstream_http, background=False)
        async with lifespan(app):
            hub = app.state.hub
            principal = Principal(id="alice", username="alice@example.test", management=True)
            await hub.acl.provision(principal)
            await redis.sadd(hub.store.key("acl:admins"), principal.id)
            token = (await hub.oauth._issue(principal, "test-client"))["access_token"]
            session = FakeSession()
            hub.upstreams.sessions["alpha"] = session
            tools = []
            for name, kind in (
                ("lookup", "read"),
                ("create_ticket", "write"),
                ("delete_ticket", "destructive"),
            ):
                tools.append(
                    {
                        "name": name,
                        "description": name,
                        "inputSchema": public_schema(
                            {
                                "type": "object",
                                "properties": {
                                    "query": {"type": "string"},
                                    "credentials": {"type": "object"},
                                    "_hub_username": {"type": "string"},
                                },
                                "required": ["query", "credentials"],
                            }
                        ),
                        "category": kind,
                        "annotated": True,
                        "accepts_credentials": True,
                        "annotations": {
                            "readOnlyHint": kind == "read",
                            "destructiveHint": kind == "destructive",
                        },
                    }
                )
            await hub.store.publish_catalog(
                {
                    "alpha": {
                        "tools": tools,
                        "status": "connected",
                        "tools_validated": True,
                        "policy": "both",
                        "code_version": "abc123",
                        "circuit_open": False,
                    }
                }
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=settings.hub_public_url
            ) as client:
                yield Harness(app, client, {"Authorization": "Bearer " + token}, principal, session)
    await redis.aclose()


@asynccontextmanager
async def lifespan(app):
    """Keep AnyIO entry/exit in one task, as a real ASGI server does."""
    ready = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def owner():
        try:
            async with app.router.lifespan_context(app):
                ready.set_result(None)
                await stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(exc)
            else:
                raise

    task = asyncio.create_task(owner())
    try:
        await ready
        yield
    finally:
        stop.set()
        await task
