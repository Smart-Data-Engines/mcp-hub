"""Starter discovery and explicit, permission-checked GitHub connection setup."""

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .http import body, context
from .models import HubError
from .starter_code.v1.github_client import connection, test_connection
from .starters import catalog
from .store import digest


async def github_access(request: Request):
    hub, ctx = request.app.state.hub, context(request)
    definition = await hub.runtime.definition(request.path_params["name"])
    access = await hub.gateway.access(ctx)
    if not access.permits(definition.name, "read"):
        raise HubError("Read access to this server is required", 403)
    if definition.starter_id != "github":
        raise HubError("This server does not use the GitHub starter", 404)
    return hub, ctx, definition, access


def safe_status(values: dict[str, Any]) -> dict:
    return {
        "configured": [
            name
            for name in ["token", "repository"]
            if isinstance(values.get(name), str) and values[name]
        ],
        "repository": values.get("repository", "")
        if isinstance(values.get("repository", ""), str)
        else "",
    }


async def write_budget(hub, principal_id: str) -> None:
    allowed, retry = await hub.store.rate(
        "credential-writes:" + digest(principal_id), hub.settings.credential_write_rate_limit, 60
    )
    if not allowed:
        raise HubError("Personal credential update rate limit reached", 429, retry_after=retry)


async def connection_info(request: Request) -> Response:
    hub, ctx, definition, access = await github_access(request)
    personal = await hub.credentials.personal(ctx.principal.id, definition.name)
    shared = await hub.credentials.global_env(definition.name) if access.admin else {}
    saved = {
        "token": shared.get("GITHUB_TOKEN", ""),
        "repository": shared.get("GITHUB_REPOSITORY", ""),
    }
    running = (
        await hub.credentials.global_env(definition.name, running=True) if access.admin else {}
    )
    return JSONResponse(
        {
            "policy": definition.policy,
            "personal": safe_status(personal),
            "shared": safe_status(saved),
            "can_manage": access.admin or definition.owner == ctx.principal.id,
            "can_change_policy": access.admin,
            "can_configure_shared": access.admin,
            "only_mine": (await hub.credentials.modes(ctx.principal.id)).get(
                definition.name, False
            ),
            "restart_required": definition.status == "running"
            and any(
                shared.get(k, "") != running.get(k, "")
                for k in ["GITHUB_TOKEN", "GITHUB_REPOSITORY"]
            ),
            "token_url": "https://github.com/settings/personal-access-tokens/new",
            "guide_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
            "permissions": "Select the repository and give Metadata, Issues and Pull requests read access. Your organization may require approval.",
        }
    )


async def write_connection(request: Request) -> Response:
    hub, ctx, definition, access = await github_access(request)
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
        or set(values) - {"token", "repository"}
        or any(not isinstance(v, str) or len(v) > 4096 for v in values.values())
    ):
        raise HubError("Connection values must contain only token and repository text fields", 422)
    changes = {k: v.strip() for k, v in values.items() if v.strip()}
    if policy == "global_only":
        shared = await hub.credentials.global_env(definition.name)
        merged = {
            "token": shared.get("GITHUB_TOKEN", ""),
            "repository": shared.get("GITHUB_REPOSITORY", ""),
            **changes,
        }
        connection(merged)
        await hub.credentials.patch_global_env(
            definition.name, {"GITHUB_" + k.upper(): v for k, v in changes.items()}, []
        )
    else:
        for _ in range(8):
            key = hub.store.key(hub.credentials._value_key(ctx.principal.id, definition.name))
            original = await hub.store.redis.get(key)
            merged = hub.credentials.cipher.decrypt(original) if original else {}
            merged.update(changes)
            connection(merged)
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
    hub, ctx, definition, access = await github_access(request)
    await write_budget(hub, ctx.principal.id)
    if definition.policy == "global_only":
        if not access.admin:
            raise HubError("Only an administrator may remove the shared connection", 403)
        await hub.credentials.patch_global_env(
            definition.name, {}, ["GITHUB_TOKEN", "GITHUB_REPOSITORY"]
        )
    else:
        await hub.credentials.delete(ctx.principal.id, definition.name)
    return Response(status_code=204)


async def check_connection(request: Request) -> Response:
    hub, ctx, definition, _ = await github_access(request)
    allowed, retry = await hub.store.rate("starter-tests:" + digest(ctx.principal.id), 10, 60)
    if not allowed:
        raise HubError("Connection test limit reached. Try again shortly", 429, retry_after=retry)
    resolved = await hub.credentials.resolve(
        ctx.principal,
        definition.name,
        definition.policy,
        None,
        required_fields=["token", "repository"],
    )
    if resolved.source == "none":
        shared = await hub.credentials.global_env(definition.name)
        values = {
            "token": shared.get("GITHUB_TOKEN", ""),
            "repository": shared.get("GITHUB_REPOSITORY", ""),
        }
    else:
        values = resolved.credentials
    result = await test_connection(hub.http, values)
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
