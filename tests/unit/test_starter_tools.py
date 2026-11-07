import json

import httpx
import pytest

from mcp_hub.models import HubError
from mcp_hub.security import scrub, secret_values
from mcp_hub.starter_code.v1 import demo, github

IDENTITY = {
    "_hub_user_id": "test-user",
    "_hub_username": "user@example.test",
    "_hub_principal": "human",
}


def test_repository_is_visible_metadata_while_tokens_remain_redacted():
    values = {"token": "synthetic-github-secret", "repository": "sample/project"}
    known = secret_values(values)
    result = scrub(
        {"repository": "sample/project", "message": "synthetic-github-secret"}, secrets=known
    )
    assert result["repository"] == "sample/project"
    assert "synthetic-github-secret" not in json.dumps(result)


async def test_demo_proves_verified_caller_and_rejects_anonymous_calls():
    assert await demo.hello("friend", IDENTITY) == "Hello friend, called by user@example.test!"
    assert await demo.who_am_i(IDENTITY) == IDENTITY
    for value in [None, {}, {"_hub_username": "fake"}, {**IDENTITY, "_hub_principal": "anonymous"}]:
        with pytest.raises(ValueError, match="Sign in"):
            await demo.hello(credentials=value)


async def test_every_starter_tool_is_readonly_and_has_explicit_caller_contract():
    for server, names in [
        (demo.mcp, {"hello", "who_am_i"}),
        (
            github.mcp,
            {
                "get_repository",
                "list_issues",
                "get_issue",
                "list_pull_requests",
                "get_pull_request",
            },
        ),
    ]:
        tools = await server.list_tools()
        assert {t.name for t in tools} == names
        for tool in tools:
            assert tool.annotations.readOnlyHint and not tool.annotations.destructiveHint
            assert "credentials" in tool.inputSchema["properties"]


async def test_github_tools_use_each_callers_repository_and_token_without_shared_leakage(
    monkeypatch,
):
    calls = []

    def provider(request):
        calls.append(request)
        assert request.method == "GET" and request.url.host == "api.github.com"
        if request.url.path.endswith("/issues") or request.url.path.endswith("/pulls"):
            return httpx.Response(
                200, json=[{"number": 1, "title": "Example", "user": {"login": "author"}}]
            )
        return httpx.Response(
            200,
            json={
                "full_name": "/".join(request.url.path.split("/")[2:4]),
                "number": 1,
                "title": "Example",
                "body": "x" * 13000,
                "user": {"login": "author"},
            },
        )

    monkeypatch.setattr(
        github, "client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(provider))
    )
    monkeypatch.setenv("GITHUB_TOKEN", "shared-secret")
    monkeypatch.setenv("GITHUB_REPOSITORY", "shared/repository")
    a = {**IDENTITY, "token": "personal-first", "repository": "first/repository"}
    b = {**IDENTITY, "token": "personal-second", "repository": "second/repository"}
    assert (await github.get_repository(a))["full_name"] == "first/repository"
    assert (await github.list_issues(credentials=b))["repository"] == "second/repository"
    assert (await github.get_issue(1, a))["body_truncated"]
    assert (await github.list_pull_requests(credentials=b))["items"][0]["kind"] == "pull_request"
    assert (await github.get_pull_request(1, a))["body_truncated"]
    assert [r.headers["Authorization"] for r in calls] == [
        "Bearer personal-first",
        "Bearer personal-second",
        "Bearer personal-first",
        "Bearer personal-second",
        "Bearer personal-first",
    ]
    assert "shared-secret" not in json.dumps([str(r.url) for r in calls])
    with pytest.raises(HubError):
        github.account({**IDENTITY, "token": "partial-personal"})
    assert github.account(IDENTITY) == ("shared-secret", "shared/repository")


@pytest.mark.parametrize(
    "operation,args",
    [
        (github.get_issue, {"number": 0}),
        (github.get_pull_request, {"number": True}),
        (github.list_issues, {"state": "invalid"}),
        (github.list_pull_requests, {"limit": 21}),
    ],
)
async def test_invalid_tool_inputs_never_contact_github(operation, args, monkeypatch):
    # Validation prevents an HTTP request even when using the tool directly.
    async def provider(request):
        raise AssertionError("Invalid input must not contact GitHub")

    monkeypatch.setattr(
        github, "client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(provider))
    )
    with pytest.raises(HubError):
        await operation(
            credentials={**IDENTITY, "token": "synthetic-token", "repository": "example/project"},
            **args,
        )
