"""Bounded, GET-only GitHub.com access shared by the starter and connection test."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx

from mcp_hub.models import HubError

API = "https://api.github.com"
MAX_RESPONSE = 2 * 1024 * 1024
REPOSITORY = re.compile(r"^([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})$", re.ASCII)


def connection(values: dict[str, Any]) -> tuple[str, str]:
    token, repository = values.get("token"), values.get("repository")
    if not isinstance(token, str) or not token.strip():
        raise HubError("Add a GitHub personal access token to this connection", 422)
    token = token.strip()
    if len(token) > 4096 or any(ord(c) <= 32 or ord(c) >= 127 for c in token):
        raise HubError("GitHub token must be a single valid token without spaces", 422)
    if not isinstance(repository, str):
        raise HubError("Enter a repository as owner/repository", 422)
    repository = repository.strip()
    match = REPOSITORY.fullmatch(repository)
    if not match or any(part in {".", ".."} for part in match.groups()):
        raise HubError("Enter a GitHub.com repository as owner/repository, without a URL", 422)
    return token, repository


def bounded_number(number: int) -> int:
    if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 2_147_483_647:
        raise HubError("Issue or pull request number must be a positive integer", 422)
    return number


def bounded_list(state: str, limit: int) -> dict[str, str | int]:
    if state not in {"open", "closed", "all"}:
        raise HubError("State must be open, closed or all", 422)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
        raise HubError("Limit must be between 1 and 20", 422)
    return {"state": state, "per_page": limit, "page": 1}


async def get(
    client: httpx.AsyncClient,
    token: str,
    repository: str,
    operation: str = "repository",
    *,
    number: int | None = None,
    params: dict | None = None,
) -> Any:
    token, repository = connection({"token": token, "repository": repository})
    # Paths are selected here; no provider URL, redirect or pagination link is followed.
    paths = {
        "user": "/user",
        "repository": f"/repos/{repository}",
        "issues": f"/repos/{repository}/issues",
        "pulls": f"/repos/{repository}/pulls",
    }
    if operation not in paths:
        raise HubError("Unsupported GitHub starter operation", 422)
    path = paths[operation]
    if number is not None:
        if operation not in {"issues", "pulls"}:
            raise HubError("Unsupported GitHub starter operation", 422)
        path += "/" + str(bounded_number(number))
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "Accept-Encoding": "identity",
    }
    try:
        async with client.stream(
            "GET", API + path, params=params, headers=headers, follow_redirects=False, timeout=15
        ) as response:
            if response.status_code == 401:
                raise HubError(
                    "GitHub rejected this token. Check its value and expiration date", 422
                )
            if response.status_code == 429 or (
                response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"
            ):
                raise HubError(
                    "GitHub API rate limit reached. Try again after the limit resets", 429
                )
            if response.status_code in {403, 404}:
                raise HubError(
                    "GitHub access is unavailable. Check owner/repository, the token's selected repositories, read permissions and any organization approval",
                    422,
                )
            if response.status_code != 200:
                raise HubError(
                    "GitHub could not complete this read. Check the connection and try again", 502
                )
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise HubError("GitHub returned an unsupported compressed response", 502)
            payload = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=65536):
                if len(payload) + len(chunk) > MAX_RESPONSE:
                    raise HubError("GitHub response is too large. Request fewer results", 413)
                payload.extend(chunk)
            value = json.loads(payload)
            listing = operation in {"issues", "pulls"} and number is None
            if (
                listing
                and (
                    not isinstance(value, list) or any(not isinstance(item, dict) for item in value)
                )
            ) or (not listing and not isinstance(value, dict)):
                raise HubError("GitHub returned an unexpected response", 502)
            return value
    except (httpx.HTTPError, ValueError, UnicodeError) as exc:
        raise HubError(
            "GitHub could not be reached or returned an invalid response. Try again", 502
        ) from exc


def summary(item: dict[str, Any], *, details: bool = False) -> dict[str, Any]:
    value = {key: item.get(key) for key in ["number", "title", "state", "html_url", "updated_at"]}
    value["author"] = (item.get("user") or {}).get("login")
    value["kind"] = "pull_request" if "pull_request" in item else "issue"
    if details:
        body = item.get("body") or ""
        value.update(body=str(body)[:12000], body_truncated=len(str(body)) > 12000)
    return value


async def test_connection(client: httpx.AsyncClient, values: dict[str, Any]) -> dict:
    token, repository = connection(values)
    try:
        async with asyncio.timeout(25):
            repo = await get(client, token, repository)
            user = await get(client, token, repository, "user")
            await get(client, token, repository, "issues", params={"per_page": 1})
            await get(client, token, repository, "pulls", params={"per_page": 1})
    except TimeoutError as exc:
        raise HubError("The GitHub connection test timed out. Try again shortly", 504) from exc
    if (
        not isinstance(repo, dict)
        or not isinstance(user, dict)
        or not user.get("login")
        or not repo.get("full_name")
    ):
        raise HubError("GitHub returned an unexpected connection response", 502)
    return {
        "ok": True,
        "account": user["login"],
        "repository": repo["full_name"],
        "private": bool(repo.get("private")),
        "message": f"Connected as {user['login']} to {repo['full_name']}",
        "checked": ["account", "repository", "issues", "pull_requests"],
        "note": "Account, repository, issue and pull request read access verified.",
    }
