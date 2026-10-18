"""Public server-author helper: authenticated MCP plus heartbeat registration."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
from typing import TYPE_CHECKING

import httpx
import uvicorn
from starlette.types import ASGIApp

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

log = logging.getLogger(__name__)


class RequireHubSecret:
    def __init__(self, app, expected: str):
        if not expected:
            raise ValueError(
                "HUB_UPSTREAM_SECRET is required; refusing an unauthenticated MCP endpoint"
            )
        self.app, self.expected = app, expected.encode()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            supplied = dict(scope.get("headers", [])).get(b"x-hub-upstream-secret", b"")
            if not hmac.compare_digest(supplied, self.expected):
                body = b'{"error":"Unauthorized"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


async def heartbeat() -> None:
    hub = os.environ.get("HUB_URL")
    if not hub:
        return
    interval = max(1, int(os.environ.get("HEARTBEAT_INTERVAL", "60")))
    delay = 1
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        while True:
            try:
                response = await client.post(
                    hub.rstrip("/") + "/register",
                    json={
                        "name": os.environ["SERVER_NAME"],
                        "url": os.environ["SERVER_URL"],
                        "code_version": os.environ.get("HUB_CODE_VERSION", ""),
                    },
                    headers={"x-hub-secret": os.environ.get("HUB_REGISTRATION_SECRET", "")},
                )
                if response.status_code not in {201, 409}:
                    raise RuntimeError("Registration rejected")
                delay = 1
                await asyncio.sleep(interval)
            except (httpx.HTTPError, RuntimeError, KeyError) as exc:
                log.warning("Hub registration unavailable: %s", type(exc).__name__)
                await asyncio.sleep(delay)
                delay = min(interval, delay * 2)


async def _run(app: ASGIApp) -> None:
    app = RequireHubSecret(app, os.environ.get("HUB_UPSTREAM_SECRET", ""))

    class ReadyServer(uvicorn.Server):
        def __init__(self, config):
            super().__init__(config)
            self.ready = asyncio.Event()

        async def startup(self, sockets=None) -> None:
            await super().startup(sockets)
            if self.started:
                self.ready.set()

    server = ReadyServer(
        uvicorn.Config(app, host="0.0.0.0", port=3000, log_level="info", access_log=False)
    )
    serving = asyncio.create_task(server.serve())
    waiting = asyncio.create_task(server.ready.wait())
    await asyncio.wait({serving, waiting}, return_when=asyncio.FIRST_COMPLETED)
    waiting.cancel()
    await asyncio.gather(waiting, return_exceptions=True)
    registering = asyncio.create_task(heartbeat()) if server.started else None
    try:
        await serving
    finally:
        if registering:
            registering.cancel()
            await asyncio.gather(registering, return_exceptions=True)


def serve(mcp: FastMCP) -> None:
    serve_app(mcp.streamable_http_app())


def serve_app(app: ASGIApp) -> None:
    """Serve an MCP ASGI application with authentication and Hub registration.

    The worker owns its SDK version; the gateway's Python SDK is not imported here.
    """
    from .security import configure_logging

    configure_logging()
    asyncio.run(_run(app))


def scaffold(name: str, owner: str) -> dict[str, str]:
    import yaml

    return {
        "server.py": '''"""A tool adapter; edit tools, keep authenticated serve(mcp)."""
import os
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from mcp_hub.upstream import serve

mcp = FastMCP(os.environ["SERVER_NAME"], stateless_http=True, json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))

@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True))
async def hello(name: str = "world", credentials: dict | None = None) -> str:
    """Return a greeting from this server; demonstrates authenticated caller identity."""
    caller = (credentials or {}).get("_hub_username")
    if not caller:
        raise ValueError("An authenticated caller is required")
    return f"Hello {name}, called by {caller}!"

if __name__ == "__main__":
    serve(mcp)
''',
        "requirements.txt": "mcp>=1.30,<2\n",
        "manifest.yaml": yaml.safe_dump({"name": name, "owner": owner, "contract_version": 1}),
        "env.yaml": "env: []\nuser_env: []\n",
        "docker.yaml": 'memory: "512m"\ncpus: "1.0"\n',
    }
