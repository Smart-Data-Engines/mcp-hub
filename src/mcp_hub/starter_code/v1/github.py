"""A small, complete GitHub.com starter. Every operation is GET-only."""

import os

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from mcp_hub.tls import trust
from mcp_hub.upstream import serve

if __package__:
    from .github_client import bounded_list, connection, get, summary
else:
    from github_client import bounded_list, connection, get, summary  # type: ignore[no-redef]

mcp = FastMCP(
    os.environ.get("SERVER_NAME", "github"),
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


def account(credentials: dict | None) -> tuple[str, str]:
    values = credentials or {}
    if (
        not values.get("_hub_user_id")
        or not values.get("_hub_username")
        or values.get("_hub_principal") not in {"human", "bot"}
    ):
        raise ValueError("Sign in to MCP Hub before using the GitHub starter")
    # A partial personal connection must never borrow the shared account's fields.
    if "token" in values or "repository" in values:
        return connection(values)
    return connection(
        {"token": os.environ.get("GITHUB_TOKEN"), "repository": os.environ.get("GITHUB_REPOSITORY")}
    )


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=trust(os.environ.get("HUB_CA_BUNDLE", "")), trust_env=False, follow_redirects=False
    )


@mcp.tool(annotations=READ)
async def get_repository(credentials: dict | None = None) -> dict:
    """Read the repository selected in your saved GitHub connection."""
    token, repository = account(credentials)
    async with client() as http:
        value = await get(http, token, repository)
    return {
        key: value.get(key)
        for key in ["full_name", "description", "html_url", "private", "default_branch", "archived"]
    }


@mcp.tool(annotations=READ)
async def list_issues(
    state: str = "open", limit: int = 10, credentials: dict | None = None
) -> dict:
    """List repository issues (GitHub's issues feed can also contain pull requests; kind distinguishes them)."""
    token, repository = account(credentials)
    params = bounded_list(state, limit)
    async with client() as http:
        values = await get(http, token, repository, "issues", params=params)
    return {
        "repository": repository,
        "items": [summary(value) for value in values],
        "limit": limit,
        "note": "Use get_issue or get_pull_request to read details.",
    }


@mcp.tool(annotations=READ)
async def get_issue(number: int, credentials: dict | None = None) -> dict:
    """Read one issue by number from the selected repository; long bodies are explicitly truncated."""
    token, repository = account(credentials)
    async with client() as http:
        value = await get(http, token, repository, "issues", number=number)
    return {"repository": repository, **summary(value, details=True)}


@mcp.tool(annotations=READ)
async def list_pull_requests(
    state: str = "open", limit: int = 10, credentials: dict | None = None
) -> dict:
    """List pull requests from the selected repository."""
    token, repository = account(credentials)
    params = bounded_list(state, limit)
    async with client() as http:
        values = await get(http, token, repository, "pulls", params=params)
    return {
        "repository": repository,
        "items": [{**summary(value), "kind": "pull_request"} for value in values],
        "limit": limit,
    }


@mcp.tool(annotations=READ)
async def get_pull_request(number: int, credentials: dict | None = None) -> dict:
    """Read one pull request by number from the selected repository."""
    token, repository = account(credentials)
    async with client() as http:
        value = await get(http, token, repository, "pulls", number=number)
    return {
        "repository": repository,
        **summary(value, details=True),
        "kind": "pull_request",
        "draft": bool(value.get("draft")),
        "merged": bool(value.get("merged")),
        "head": (value.get("head") or {}).get("ref"),
        "base": (value.get("base") or {}).get("ref"),
    }


if __name__ == "__main__":
    serve(mcp)
