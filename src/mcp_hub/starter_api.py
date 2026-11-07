"""Starter discovery and explicit, permission-checked provider connections."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .http import body, context
from .models import HubError
from .security import scrub, secret_values
from .starter_code.v1 import github_client, notion_client
from .starters import catalog
from .store import digest


@dataclass(frozen=True)
class Provider:
    name: str
    fields: tuple[tuple[str, str], ...]
    validate: Callable[[dict[str, Any]], Any]
    test: Callable[[httpx.AsyncClient, dict[str, Any]], Awaitable[dict]]
    token_url: str
    guide_url: str
    permissions: str

    def shared_values(self, values: dict) -> dict:
        return {name: values.get(env, "") for name, env in self.fields}


PROVIDERS = {
    "github": Provider(
        "GitHub",
        (("token", "GITHUB_TOKEN"), ("repository", "GITHUB_REPOSITORY")),
        github_client.connection,
        github_client.test_connection,
        "https://github.com/settings/personal-access-tokens/new",
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        "Select the repository and give Metadata, Issues and Pull requests read access. Your organization may require approval.",
    ),
    "notion": Provider(
        "Notion",
        (("token", "NOTION_TOKEN"),),
        notion_client.connection,
        notion_client.test_connection,
        "https://www.notion.so/profile/integrations",
        "https://developers.notion.com/reference/capabilities",
        "Create an internal Notion connection with Read content capability. In Notion, open each page or database you want to share, choose Connections, and add this connection. Content in child pages is included according to Notion's sharing rules.",
    ),
}


async def provider_access(request: Request):
    hub, ctx = request.app.state.hub, context(request)
    definition = await hub.runtime.definition(request.path_params["name"])
    access = await hub.gateway.access(ctx)
    if not access.permits(definition.name, "read"):
        raise HubError("Read access to this server is required", 403)
    provider = PROVIDERS.get(definition.starter_id)
    if provider is None:
        raise HubError("This server does not use a provider starter", 404)
    return hub, ctx, definition, access, provider


def safe_status(values: dict[str, Any], provider: Provider) -> dict:
    return {
        "configured": [
            name
            for name, _ in provider.fields
            if isinstance(values.get(name), str) and values[name]
        ],
        **(
            {
                "repository": values.get("repository", "")
                if isinstance(values.get("repository", ""), str)
                else ""
            }
            if any(name == "repository" for name, _ in provider.fields)
            else {}
        ),
    }


async def write_budget(hub, principal_id: str) -> None:
    allowed, retry = await hub.store.rate(
        "credential-writes:" + digest(principal_id), hub.settings.credential_write_rate_limit, 60
    )
    if not allowed:
        raise HubError("Personal credential update rate limit reached", 429, retry_after=retry)


async def connection_info(request: Request) -> Response:
    hub, ctx, definition, access, provider = await provider_access(request)
    personal = await hub.credentials.personal(ctx.principal.id, definition.name)
    shared = await hub.credentials.global_env(definition.name) if access.admin else {}
    saved = provider.shared_values(shared)
    running = (
        await hub.credentials.global_env(definition.name, running=True) if access.admin else {}
    )
    return JSONResponse(
        {
            "policy": definition.policy,
            "provider": definition.starter_id,
            "required_fields": [name for name, _ in provider.fields],
            "personal": safe_status(personal, provider),
            "shared": safe_status(saved, provider),
            "can_manage": access.admin or definition.owner == ctx.principal.id,
            "can_change_policy": access.admin,
            "can_configure_shared": access.admin,
            "only_mine": (await hub.credentials.modes(ctx.principal.id)).get(
                definition.name, False
            ),
            "restart_required": definition.status == "running"
            and any(shared.get(k, "") != running.get(k, "") for _, k in provider.fields),
            "token_url": provider.token_url,
            "guide_url": provider.guide_url,
            "permissions": provider.permissions,
        }
    )


async def write_connection(request: Request) -> Response:
    hub, ctx, definition, access, provider = await provider_access(request)
    await write_budget(hub, ctx.principal.id)
    data = await body(request)
    if set(data) - {"policy", "values"}:
        raise HubError("Unsupported connection fields", 422)
    policy = data.get("policy", definition.policy)
    if not isinstance(policy, str) or policy not in {"user_only", "global_only"}:
        raise HubError("Choose personal connections or a shared connection", 422)
    if (policy != definition.policy or policy == "global_only") and not access.admin:
        raise HubError(
            "Only an administrator may configure a shared connection or change its mode", 403
        )
    values = data.get("values", {})
    if (
        not isinstance(values, dict)
        or set(values) - {name for name, _ in provider.fields}
        or any(not isinstance(v, str) or len(v) > 4096 for v in values.values())
    ):
        raise HubError("Use only the connection's declared text fields", 422)
    changes = {k: v.strip() for k, v in values.items() if v.strip()}
    if policy == "global_only":
        shared = await hub.credentials.global_env(definition.name)
        merged = {**provider.shared_values(shared), **changes}
        provider.validate(merged)
        await hub.credentials.patch_global_env(
            definition.name,
            {env: changes[name] for name, env in provider.fields if name in changes},
            [],
        )
    else:
        for _ in range(8):
            key = hub.store.key(hub.credentials._value_key(ctx.principal.id, definition.name))
            original = await hub.store.redis.get(key)
            merged = hub.credentials.cipher.decrypt(original) if original else {}
            merged.update(changes)
            provider.validate(merged)
            try:
                await hub.credentials.save(
                    ctx.principal.id, definition.name, merged, compare=True, expected_value=original
                )
                break
            except HubError as exc:
                if exc.code != "connection_changed":
                    raise
        else:
            raise HubError("Your connection changed concurrently. Try again.", 409)
    if policy != definition.policy:
        definition.policy = policy
        await hub.runtime.save(definition, fields={"policy"})
    return Response(status_code=204)


async def remove_connection(request: Request) -> Response:
    hub, ctx, definition, access, provider = await provider_access(request)
    await write_budget(hub, ctx.principal.id)
    if definition.policy == "global_only":
        if not access.admin:
            raise HubError("Only an administrator may remove the shared connection", 403)
        await hub.credentials.patch_global_env(
            definition.name, {}, [env for _, env in provider.fields]
        )
    else:
        await hub.credentials.delete(ctx.principal.id, definition.name)
    return Response(status_code=204)


async def check_connection(request: Request) -> Response:
    hub, ctx, definition, _, provider = await provider_access(request)
    allowed, retry = await hub.store.rate("starter-tests:" + digest(ctx.principal.id), 10, 60)
    if not allowed:
        raise HubError("Connection test limit reached. Try again shortly", 429, retry_after=retry)
    resolved = await hub.credentials.resolve(
        ctx.principal,
        definition.name,
        definition.policy,
        None,
        required_fields=[name for name, _ in provider.fields],
    )
    if resolved.source == "none":
        shared = await hub.credentials.global_env(definition.name)
        values = provider.shared_values(shared)
    else:
        values = resolved.credentials
    result = scrub(await provider.test(hub.http, values), secrets=secret_values(values))
    return JSONResponse(
        {**result, "connection": "shared" if resolved.source == "none" else "personal"}
    )


def starter_routes() -> list[Route]:
    async def starters(request: Request) -> Response:
        return JSONResponse({"starters": catalog()})

    base = "/admin/api/servers-dynamic/{name}/starter-connection"
    return [
        Route("/admin/api/starters", starters),
        Route(base, connection_info),
        Route(base, write_connection, methods=["PATCH"]),
        Route(base, remove_connection, methods=["DELETE"]),
        Route(base + "/test", check_connection, methods=["POST"]),
    ]
