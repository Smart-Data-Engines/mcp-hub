"""A small Notion starter written against the public API. All tools read only."""

import os

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from mcp_hub.tls import trust
from mcp_hub.upstream import serve

if __package__:
    from .notion_client import bounded_item, connection, request, result_page
else:
    from notion_client import bounded_item, connection, request, result_page  # type: ignore[no-redef]

mcp = FastMCP(
    os.environ.get("SERVER_NAME", "notion"),
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
READ = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True)


def account(credentials: dict | None) -> str:
    values = credentials or {}
    if (
        not values.get("_hub_user_id")
        or not values.get("_hub_username")
        or values.get("_hub_principal") not in {"human", "bot"}
    ):
        raise ValueError("Sign in to MCP Hub before using the Notion starter")
    if "token" in values:
        return connection(values)
    return connection({"token": os.environ.get("NOTION_TOKEN")})


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=trust(os.environ.get("HUB_CA_BUNDLE", "")), trust_env=False, follow_redirects=False
    )


@mcp.tool(annotations=READ)
async def search(
    query: str = "", limit: int = 10, cursor: str = "", credentials: dict | None = None
) -> dict:
    """Search accessible pages and data sources by title. This is not full-text search or a complete workspace inventory. Follow next_cursor for more results."""
    token = account(credentials)
    async with client() as http:
        return result_page(
            await request(http, token, "search", query=query, limit=limit, cursor=cursor)
        )


@mcp.tool(annotations=READ)
async def get_page(page_id: str, credentials: dict | None = None) -> dict:
    """Read a page's metadata and inline properties by ID from search. Read its content with list_blocks. Notion may paginate long property values; oversized items are explicitly truncated."""
    token = account(credentials)
    async with client() as http:
        result = bounded_item(await request(http, token, "page", item_id=page_id))
        result["properties_note"] = (
            "Notion returns inline property previews; long relations, rich text and other property values may need separate pagination in Notion. The truncation flag describes only this starter's output limit."
        )
        return result


@mcp.tool(annotations=READ)
async def list_blocks(
    block_id: str, limit: int = 10, cursor: str = "", credentials: dict | None = None
) -> dict:
    """Read one page of child blocks. Use a page ID first, then child IDs with has_children=true. Content is not fetched recursively; truncation and continuation are explicit."""
    token = account(credentials)
    async with client() as http:
        return result_page(
            await request(http, token, "blocks", item_id=block_id, limit=limit, cursor=cursor)
        )


@mcp.tool(annotations=READ)
async def get_database(database_id: str, credentials: dict | None = None) -> dict:
    """Read database metadata and its data source IDs. Use query_data_source to read rows from one of those sources."""
    token = account(credentials)
    async with client() as http:
        return bounded_item(await request(http, token, "database", item_id=database_id))


@mcp.tool(annotations=READ)
async def query_data_source(
    data_source_id: str, limit: int = 10, cursor: str = "", credentials: dict | None = None
) -> dict:
    """Read one page of rows from a data source ID returned by search or get_database. This query never modifies Notion. Follow next_cursor for more rows."""
    token = account(credentials)
    async with client() as http:
        return result_page(
            await request(http, token, "query", item_id=data_source_id, limit=limit, cursor=cursor)
        )


if __name__ == "__main__":
    serve(mcp)
