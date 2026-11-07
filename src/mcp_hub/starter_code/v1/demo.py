"""A complete starter without an external account or network dependency."""

import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from mcp_hub.upstream import serve

mcp = FastMCP(
    os.environ.get("SERVER_NAME", "demo"),
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


def caller(credentials: dict | None) -> dict:
    values = credentials or {}
    if (
        not values.get("_hub_user_id")
        or not values.get("_hub_username")
        or values.get("_hub_principal") not in {"human", "bot"}
    ):
        raise ValueError("Sign in to MCP Hub before using this starter")
    return {key: values[key] for key in ["_hub_user_id", "_hub_username", "_hub_principal"]}


@mcp.tool(annotations=READ)
async def hello(name: str = "world", credentials: dict | None = None) -> str:
    """Return a greeting using the caller identity verified by MCP Hub."""
    user = caller(credentials)
    return f"Hello {name}, called by {user['_hub_username']}!"


@mcp.tool(annotations=READ)
async def who_am_i(credentials: dict | None = None) -> dict:
    """Show your verified Hub identity. No external service or credentials are needed."""
    return caller(credentials)


if __name__ == "__main__":
    serve(mcp)
