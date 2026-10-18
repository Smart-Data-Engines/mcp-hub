"""Role-checked management API. File/source edits and secret reads are explicit."""

from __future__ import annotations

import hmac
import json
import time
from typing import Any

import yaml
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .http import body, context
from .models import ALL_CAPS, NAME, HubError, ServerDefinition, visible
from .registry import source_location, validate_files, validate_path
from .runtime import resource_limits
from .store import digest, dumps


async def role(request: Request, *, manager: bool = False):
    hub = request.app.state.hub
    access = await hub.gateway.access(context(request))
    if not access.admin and not (manager and access.manager):
        raise HubError(
            "Administrator role required"
            if not manager
            else "Administrator or manager role required",
            403,
        )
    return access


async def owner(request: Request):
    hub = request.app.state.hub
    definition = await hub.runtime.definition(request.path_params["name"])
    access = await hub.gateway.access(context(request))
    if not access.admin and definition.owner != context(request).principal.id:
        raise HubError("Only the server owner or an administrator may manage it", 403)
    return definition, access


def service_name(value: Any) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise HubError("Name must match ^[a-z0-9_-]{1,64}$", 422)
    return value


def caps(value: Any) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or item not in ALL_CAPS for item in value
    ):
        raise HubError(
            "Capabilities must be an array containing read, write and/or destructive", 422
        )
    return sorted(set(value))


async def _may_change_user(request: Request) -> None:
    access = await role(request, manager=True)
    target = request.path_params["user_id"]
    hub = request.app.state.hub
    if not access.admin and (
        target == context(request).principal.id
        or await hub.store.redis.sismember(hub.store.key("acl:admins"), target)
    ):
        raise HubError("Managers cannot change their own or administrators' access", 403)


def management_routes() -> list[Route]:
    async def whoami(request: Request) -> Response:
        hub, ctx = request.app.state.hub, context(request)
        access = await hub.gateway.access(ctx)
        catalog = await hub.store.catalog()
        permission_names = (
            set(catalog["servers"])
            | set(access.group.get("servers", {}))
            | set(access.user.get("grants", {}))
            | set(access.user.get("denies", []))
            | {
                name
                for name, definition in access.definitions.items()
                if access.admin or definition.get("owner") == ctx.principal.id
            }
        )
        ui = await hub.store.get("oauth:ui:" + digest(request.cookies.get("hub_ui", "")))
        return JSONResponse(
            {
                "principal": ctx.principal.model_dump(),
                "admin": access.admin,
                "manager": access.manager,
                "group": access.user.get("group"),
                "permissions": {
                    name: {**access.sources(name), "available": name in catalog["servers"]}
                    for name in sorted(permission_names)
                },
                "runtime_enabled": hub.runtime.verified,
                "source_editing_enabled": not hub.settings.registry_read_only,
                "idp_provider": hub.settings.idp_provider,
                "interaction_csrf": ui["csrf"]
                if ui and ui["principal_id"] == ctx.principal.id
                else None,
            }
        )

    async def users(request: Request) -> Response:
        await role(request, manager=True)
        store = request.app.state.hub.store
        return JSONResponse(
            {
                "users": [
                    json.loads(value)
                    for value in (await store.redis.hgetall(store.key("acl:users"))).values()
                ]
            }
        )

    async def user_access(request: Request) -> Response:
        await role(request, manager=True)
        hub = request.app.state.hub
        from .models import Principal

        raw = await hub.store.redis.hget(hub.store.key("acl:users"), request.path_params["user_id"])
        if not raw:
            raise HubError("User not found", 404)
        data = json.loads(raw)
        data["grants"] = data.get("grants") or {}
        data["denies"] = data.get("denies") or []
        access = await hub.acl.snapshot(
            Principal.model_validate(
                {key: data[key] for key in ("id", "username", "kind", "client_id")}
            )
        )
        catalog = await hub.store.catalog()
        return JSONResponse(
            {
                "user": data,
                "servers": {
                    name: {**access.sources(name), "available": name in catalog["servers"]}
                    for name in set(catalog["servers"])
                    | set(access.definitions)
                    | set(data.get("grants", {}))
                    | set(data.get("denies", []))
                },
            }
        )

    async def access_directory(request: Request) -> Response:
        await role(request, manager=True)
        hub = request.app.state.hub
        people = await hub.acl.directory()
        catalog = (await hub.store.catalog())["servers"]
        definitions = await hub.store.dynamic()
        raw_groups = await hub.store.redis.hgetall(hub.store.key("acl:groups"))
        selected = request.query_params.get("server")
        if selected and selected not in set(catalog) | set(definitions):
            raise HubError("Server not found. Refresh the server list and try again.", 404)
        return JSONResponse(
            {
                "users": [
                    {**p.user, "admin": p.admin, "manager": p.manager}
                    for p in sorted(people, key=lambda p: (p.principal.username, p.principal.id))
                ],
                "groups": {
                    name: {**(group := json.loads(raw)), "servers": group.get("servers") or {}}
                    for name, raw in raw_groups.items()
                    if name != "_bots"
                },
                "servers": [
                    {
                        "name": name,
                        "description": definitions.get(name, {}).get("description", ""),
                        "owner": definitions.get(name, {}).get("owner", ""),
                        "visibility": definitions.get(name, {}).get("visibility", "public"),
                        "status": definitions.get(name, {}).get(
                            "status", catalog.get(name, {}).get("status", "offline")
                        ),
                        "available": name in catalog,
                        "managed": name in definitions,
                    }
                    for name in sorted(set(catalog) | set(definitions))
                ],
                "members": {
                    p.principal.id: {**p.sources(selected), "available": selected in catalog}
                    for p in people
                }
                if selected
                else {},
            }
        )

    async def save_access(request: Request) -> Response:
        await _may_change_user(request)
        data = await body(request)
        mode = data.get("mode")
        if not isinstance(mode, str) or mode not in {"inherit", "grant", "block"}:
            raise HubError("Choose group access, personal access or blocked access", 422)
        capabilities = caps(data.get("caps", []))
        if mode == "grant" and not capabilities:
            raise HubError("Select at least one permission", 422)
        hub = request.app.state.hub
        await hub.acl.set_server_access(
            context(request).principal,
            request.path_params["user_id"],
            service_name(request.path_params["server"]),
            mode,
            capabilities,
        )
        hub.upstreams.wake.set()
        return await user_access(request)

    async def change_group(request: Request) -> Response:
        if request.method == "GET":
            return await user_access(request)
        await _may_change_user(request)
        data = await body(request)
        group = service_name(data.get("group"))
        if group == "_bots":
            raise HubError("The bot group is assigned automatically", 409)
        await request.app.state.hub.acl.change_user(request.path_params["user_id"], "group", group)
        return Response(status_code=204)

    async def personal(request: Request) -> Response:
        await _may_change_user(request)
        action, server = request.path_params["action"], service_name(request.path_params["server"])
        if action not in {"grant", "deny"}:
            raise HubError("Action must be grant or deny", 404)
        operation = ("un" if request.method == "DELETE" else "") + action
        payload: Any = server
        if request.method == "POST" and action == "grant":
            data = await body(request)
            payload = {"server": server, "caps": caps(data.get("caps", ["read"]))}
        await request.app.state.hub.acl.change_user(
            request.path_params["user_id"], operation, payload
        )
        return Response(status_code=204)

    async def revoke_user(request: Request) -> Response:
        await _may_change_user(request)
        await request.app.state.hub.oauth.revoke_principal(request.path_params["user_id"])
        return Response(status_code=204)

    async def groups(request: Request) -> Response:
        await role(request)
        hub = request.app.state.hub
        if request.method == "GET":
            return JSONResponse(
                {
                    "groups": {
                        key: json.loads(value)
                        for key, value in (
                            await hub.store.redis.hgetall(hub.store.key("acl:groups"))
                        ).items()
                        if key != "_bots"
                    }
                }
            )
        data = await body(request)
        name = service_name(request.path_params.get("name") or data.get("name"))
        if name == "_bots":
            raise HubError("The bot group is reserved and always starts empty", 409)
        servers = data.get("servers", {})
        if not isinstance(servers, dict):
            raise HubError("servers must map server names to capability arrays")
        value = {
            "servers": {service_name(key): caps(value) for key, value in servers.items()},
            "approval_required": bool(data.get("approval_required", False)),
        }
        if request.method == "POST":
            created = await hub.store.redis.hsetnx(hub.store.key("acl:groups"), name, dumps(value))
            if not created:
                raise HubError("Group already exists", 409)
        else:
            await hub.store.redis.hset(hub.store.key("acl:groups"), name, dumps(value))
        return JSONResponse({"name": name, **value}, 201 if request.method == "POST" else 200)

    async def delete_group(request: Request) -> Response:
        await role(request)
        await request.app.state.hub.acl.delete_group(request.path_params["name"])
        return Response(status_code=204)

    async def admins(request: Request) -> Response:
        await role(request)
        hub = request.app.state.hub
        if request.method == "GET":
            return JSONResponse(
                {
                    "managed": bool(hub.settings.admin_emails),
                    "admins": sorted(await hub.store.redis.smembers(hub.store.key("acl:admins"))),
                    "managers": sorted(
                        await hub.store.redis.smembers(hub.store.key("acl:managers"))
                    ),
                }
            )
        if hub.settings.admin_emails:
            raise HubError(
                "Administrator roles are managed by the deployment's ADMIN_EMAILS policy", 403
            )
        user_id = request.path_params["user_id"]
        if request.method == "DELETE":
            await hub.acl.remove_admin(user_id)
        else:
            if not await hub.store.redis.hexists(hub.store.key("acl:users"), user_id):
                raise HubError("User must sign in before receiving a role", 404)
            await hub.store.redis.sadd(hub.store.key("acl:admins"), user_id)
        return Response(status_code=204)

    async def managers(request: Request) -> Response:
        await role(request)
        hub = request.app.state.hub
        function = hub.store.redis.srem if request.method == "DELETE" else hub.store.redis.sadd
        await function(hub.store.key("acl:managers"), request.path_params["user_id"])
        return Response(status_code=204)

    async def clients(request: Request) -> Response:
        await role(request)
        hub = request.app.state.hub
        if request.method == "POST":
            return JSONResponse(
                await hub.oauth.register_client(
                    {**await body(request), "grant_types": ["client_credentials"]}, bot=True
                ),
                201,
            )
        users = await hub.store.redis.hgetall(hub.store.key("acl:users"))
        return JSONResponse(
            {
                "clients": [
                    value
                    for raw in users.values()
                    if (value := json.loads(raw)).get("kind") == "bot"
                ]
            }
        )

    async def credentials(request: Request) -> Response:
        hub, principal = request.app.state.hub, context(request).principal
        if request.method == "GET":
            return JSONResponse(
                {
                    "services": await hub.credentials.services(principal.id),
                    "only_mine": await hub.credentials.modes(principal.id),
                }
            )
        data = await body(request)
        service = service_name(data.get("service"))
        value = data.get("credentials")
        if not isinstance(value, dict):
            raise HubError("credentials must be a JSON object", 422)
        only_mine = data.get("only_mine")
        if "only_mine" in data and not isinstance(only_mine, bool):
            raise HubError("only_mine must be a boolean", 422)
        await hub.credentials.save(principal.id, service, value, only_mine=only_mine)
        return Response(status_code=204)

    async def delete_credentials(request: Request) -> Response:
        await request.app.state.hub.credentials.delete(
            context(request).principal.id, service_name(request.path_params["service"])
        )
        return Response(status_code=204)

    async def credential_mode(request: Request) -> Response:
        hub, principal = request.app.state.hub, context(request).principal
        if request.method == "GET":
            return JSONResponse(await hub.credentials.modes(principal.id))
        data = await body(request)
        if not isinstance(data.get("only_mine"), bool):
            raise HubError("only_mine must be a boolean", 422)
        await hub.credentials.set_mode(
            principal.id, service_name(data.get("service")), data["only_mine"]
        )
        return Response(status_code=204)

    async def servers(request: Request) -> Response:
        await role(request, manager=True)
        hub = request.app.state.hub
        if request.method == "POST":
            hub.upstreams.wake.set()
            return JSONResponse({"status": "refresh_requested"}, 202)
        return JSONResponse(await hub.store.catalog())

    async def dynamic_list(request: Request) -> Response:
        hub, ctx = request.app.state.hub, context(request)
        access = await hub.gateway.access(ctx)
        if request.method == "GET":
            data = await hub.store.dynamic()
            return JSONResponse(
                {
                    "servers": [
                        value
                        for value in data.values()
                        if visible(value, ctx.principal, admin=access.admin)
                    ]
                }
            )
        data = await body(request)
        allowed = {"name", "description", "visibility", "shared_with", "autostart"}
        if access.admin:
            allowed |= {"owner", "memory_mb", "cpus"}
        if set(data) - allowed:
            raise HubError("Unsupported or privileged server fields", 403)
        definition = ServerDefinition.model_validate(
            {**data, "owner": data.get("owner", ctx.principal.id)}
        )
        return JSONResponse((await hub.runtime.create(definition)).model_dump(), 201)

    async def dynamic(request: Request) -> Response:
        definition, access = await owner(request)
        hub = request.app.state.hub
        if request.method == "GET":
            return JSONResponse(definition.model_dump())
        if request.method == "DELETE":
            await hub.runtime.delete(definition.name)
            return Response(status_code=204)
        data = await body(request)
        allowed = {
            "description",
            "visibility",
            "shared_with",
            "autostart",
            "pinned_ref",
            "idempotency",
            "approval_required",
            "approval_four_eyes",
            "call_timeout",
            "read_timeout",
        }
        if access.admin:
            allowed |= {"memory_mb", "cpus"}
        if set(data) - allowed:
            raise HubError("Unsupported or privileged server fields", 403)
        updated = ServerDefinition.model_validate({**definition.model_dump(), **data})
        if updated.read_timeout is not None and updated.read_timeout >= (
            updated.call_timeout or hub.settings.upstream_call_tool_timeout
        ):
            raise HubError("Per-request budget must be below the gateway ceiling", 422)
        if {"memory_mb", "cpus"} & set(data):
            await hub.registry.commit(
                f"{definition.owner}/{definition.name}",
                {
                    "docker.yaml": yaml.safe_dump(
                        {"memory": f"{updated.memory_mb}m", "cpus": str(updated.cpus)}
                    )
                },
                "Update administrator-approved container limits",
            )
        await hub.runtime.save(updated, fields=set(data))
        return JSONResponse(updated.model_dump())

    async def lifecycle(request: Request) -> Response:
        definition, _ = await owner(request)
        hub = request.app.state.hub
        action = request.path_params["action"]
        if action == "stop":
            result = await hub.runtime.stop(definition.name)
        elif action in {"start", "restart"}:
            result = await hub.runtime.start(definition.name, restart=action == "restart")
        else:
            raise HubError("Unknown lifecycle action", 404)
        return JSONResponse(result.model_dump())

    async def logs(request: Request) -> Response:
        definition, _ = await owner(request)
        return JSONResponse(
            {
                "logs": await request.app.state.hub.runtime.logs(
                    definition.name, int(request.query_params.get("tail", "100"))
                )
            }
        )

    async def files(request: Request) -> Response:
        definition, access = await owner(request)
        hub = request.app.state.hub
        folder = f"{definition.owner}/{definition.name}"
        if request.method == "GET":
            snapshot = await hub.registry.snapshot(folder)
            path = request.path_params.get("path")
            if path:
                validate_path(path)
                if path not in snapshot.files:
                    raise HubError("File not found", 404)
                return JSONResponse(
                    {"path": path, "content": snapshot.files[path], "commit": snapshot.commit}
                )
            return JSONResponse({"files": snapshot.files, "commit": snapshot.commit})
        data: dict[str, Any] = (
            await body(request)
            if request.method != "DELETE"
            else {"files": {request.path_params["path"]: None}, "message": "Delete source file"}
        )
        changes = data.get("files", {})
        validate_files(changes)
        if "manifest.yaml" in changes or ("docker.yaml" in changes and not access.admin):
            raise HubError("Manifest is read-only; container limits require an administrator", 403)
        if any(
            changes.get(required, "present") is None
            for required in ("server.py", "requirements.txt", "env.yaml", "docker.yaml")
        ):
            raise HubError("Required server files cannot be deleted", 409)
        if not changes:
            raise HubError("No file changes supplied")
        docker_text = changes.get("docker.yaml")
        approved_limits = resource_limits(docker_text) if isinstance(docker_text, str) else None
        commit = await hub.registry.commit(
            folder,
            changes,
            str(data.get("message", "Update MCP server")),
            str(data.get("expected_commit", "")),
        )
        if approved_limits:
            definition.memory_mb, definition.cpus = approved_limits
            await hub.runtime.save(definition, fields={"memory_mb", "cpus"})
        return JSONResponse({"commit": commit, "restart_required": True})

    async def source(request: Request) -> Response:
        definition, _ = await owner(request)
        return JSONResponse(
            {
                **source_location(
                    request.app.state.hub.settings,
                    f"{definition.owner}/{definition.name}",
                    definition.pinned_ref,
                ),
                "running_revision": definition.code_version,
            }
        )

    async def env(request: Request) -> Response:
        definition, access = await owner(request)
        hub = request.app.state.hub
        snapshot = await hub.registry.snapshot(f"{definition.owner}/{definition.name}")
        fields = yaml.safe_load(snapshot.files.get("env.yaml", "")) or {}
        if request.url.path.endswith("/env/values"):
            await role(request)
            return JSONResponse({"values": await hub.credentials.global_env(definition.name)})
        if request.method == "GET":
            values = await hub.credentials.global_env(definition.name) if access.admin else {}
            running = (
                await hub.credentials.global_env(definition.name, running=True)
                if access.admin and definition.status == "running"
                else values
            )
            return JSONResponse(
                {
                    "declared": fields.get("env", []),
                    "configured": sorted(values),
                    "user_env": fields.get("user_env", []),
                    "configuration_visible": access.admin,
                    "restart_required": {
                        key: value for key, value in values.items() if key in fields.get("env", [])
                    }
                    != running,
                }
            )
        await role(request)
        data = await body(request)
        values = data.get("values")
        if not isinstance(values, dict) or any(
            key not in fields.get("env", []) or not isinstance(value, str)
            for key, value in values.items()
        ):
            raise HubError("Global Env accepts only declared string fields", 422)
        if request.method == "PATCH":
            remove = data.get("remove", [])
            if (
                not isinstance(remove, list)
                or any(
                    not isinstance(key, str) or key not in fields.get("env", []) for key in remove
                )
                or set(remove) & set(values)
                or any(not value.strip() for value in values.values())
            ):
                raise HubError("Enter a value to replace a field, or explicitly remove it.", 422)
            await hub.credentials.patch_global_env(definition.name, values, remove)
            return Response(status_code=204)
        await hub.credentials.save_global_env(definition.name, values)
        return Response(status_code=204)

    async def user_env(request: Request) -> Response:
        hub, ctx = request.app.state.hub, context(request)
        definition = await hub.runtime.definition(request.path_params["name"])
        access = await hub.gateway.access(ctx)
        if not access.capabilities(definition.name):
            raise HubError("Server access required", 403)
        snapshot = await hub.registry.snapshot(f"{definition.owner}/{definition.name}")
        fields = yaml.safe_load(snapshot.files.get("env.yaml", "")) or {}
        return JSONResponse({"fields": fields.get("user_env", [])})

    async def policy(request: Request) -> Response:
        definition, _ = await owner(request)
        await role(request)
        if request.method == "GET":
            return JSONResponse({"policy": definition.policy})
        data = await body(request)
        if not isinstance(data.get("policy"), str) or data.get("policy") not in {
            "both",
            "user_only",
            "global_only",
        }:
            raise HubError("Policy must be both, user_only or global_only", 422)
        definition.policy = data["policy"]
        await request.app.state.hub.runtime.save(definition, fields={"policy"})
        return JSONResponse({"policy": definition.policy})

    async def approvals(request: Request) -> Response:
        hub, ctx = request.app.state.hub, context(request)
        if ctx.principal.kind != "human":
            raise HubError("Human sign-in required", 403)
        access = await hub.gateway.access(ctx)
        if request.method == "GET":
            await hub.store.redis.zremrangebyscore(
                hub.store.key("approval:_index"),
                "-inf",
                int(time.time()) - hub.settings.approval_ttl,
            )
            ids = await hub.store.redis.zrange(hub.store.key("approval:_index"), 0, -1)
            values = []
            for identifier in ids:
                value = await hub.store.get("approval:" + identifier)
                if value and (
                    value["principal"]["id"] == ctx.principal.id
                    or access.admin
                    or (
                        value.get("four_eyes")
                        and access.permits(value["tool"].partition(".")[0], "destructive")
                    )
                ):
                    values.append({key: item for key, item in value.items() if key != "arguments"})
            return JSONResponse({"approvals": values})
        ui = await hub.store.get("oauth:ui:" + digest(request.cookies.get("hub_ui", "")))
        if (
            request.headers.get("origin") != hub.settings.hub_public_url
            or not ui
            or ui["principal_id"] != ctx.principal.id
            or not hmac.compare_digest(ui["csrf"], request.headers.get("x-hub-interactive", ""))
        ):
            raise HubError("Approval requires an interactive signed-in browser session", 403)
        identifier = request.path_params["approval_id"]
        raw = await hub.store.redis.get(hub.store.key("approval:" + identifier))
        if not raw:
            raise HubError("Approval expired", 404)
        value = json.loads(raw)
        if value["status"] != "pending":
            raise HubError("Approval was already decided", 409)
        server = value["tool"].partition(".")[0]
        if not access.permits(server, "destructive"):
            raise HubError("Destructive capability required to approve", 403)
        four_eyes = bool(
            value.get("four_eyes") or access.definitions.get(server, {}).get("approval_four_eyes")
        )
        if four_eyes and value["principal"]["id"] == ctx.principal.id:
            raise HubError("A different human must approve this server's destructive actions", 403)
        if not four_eyes and value["principal"]["id"] != ctx.principal.id and not access.admin:
            raise HubError("Only the caller or an administrator may decide this approval", 403)
        decision = (await body(request)).get("decision")
        if not isinstance(decision, str) or decision not in {"approve", "reject"}:
            raise HubError("decision must be approve or reject", 422)
        value.update(
            status="approved" if decision == "approve" else "rejected", decided_by=ctx.principal.id
        )
        changed = await hub.store.script(
            """
            if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end
            local ttl=redis.call('TTL',KEYS[1]); if ttl<=0 then return 0 end
            redis.call('SET',KEYS[1],ARGV[2],'EX',ttl); return 1
        """,
            ["approval:" + identifier],
            [raw, dumps(value)],
        )
        if not changed:
            raise HubError("Approval changed concurrently", 409)
        return JSONResponse({"status": value["status"]})

    async def audit(request: Request) -> Response:
        await role(request)
        hub = request.app.state.hub
        entries = await hub.store.redis.lrange(hub.store.key("audit:spool"), -100, -1)
        return JSONResponse(
            {
                "pending_events": [json.loads(raw) for raw in reversed(entries)],
                "pending_count": await hub.store.redis.llen(hub.store.key("audit:spool")),
                "dropped": int(await hub.store.redis.get(hub.store.key("audit:dropped")) or 0),
            }
        )

    prefix = "/admin/api/servers-dynamic"
    return [
        Route("/admin/api/whoami", whoami),
        Route("/admin/api/users", users),
        Route("/admin/api/access", access_directory),
        Route("/admin/api/users/{user_id}/access/{server}", save_access, methods=["PUT"]),
        Route("/admin/api/users/{user_id}/servers", user_access),
        Route("/admin/api/users/{user_id}/personal", user_access),
        Route("/admin/api/users/{user_id}/group", change_group, methods=["GET", "PUT"]),
        Route(
            "/admin/api/users/{user_id}/personal/{action}/{server}",
            personal,
            methods=["POST", "DELETE"],
        ),
        Route("/admin/api/users/{user_id}/revoke", revoke_user, methods=["POST"]),
        Route("/admin/api/groups", groups, methods=["GET", "POST"]),
        Route("/admin/api/groups/{name}", groups, methods=["PUT"]),
        Route("/admin/api/groups/{name}", delete_group, methods=["DELETE"]),
        Route("/admin/api/admins", admins),
        Route("/admin/api/admins/{user_id}", admins, methods=["POST", "DELETE"]),
        Route("/admin/api/managers/{user_id}", managers, methods=["POST", "DELETE"]),
        Route("/admin/api/clients", clients, methods=["GET", "POST"]),
        Route("/admin/api/servers", servers, methods=["GET", "POST"]),
        Route("/admin/api/approvals", approvals),
        Route("/admin/api/approvals/{approval_id}", approvals, methods=["POST"]),
        Route("/admin/api/audit", audit),
        Route("/credentials/mode", credential_mode, methods=["GET", "POST"]),
        Route("/credentials", credentials, methods=["GET", "POST"]),
        Route("/credentials/{service}", delete_credentials, methods=["DELETE"]),
        Route(prefix, dynamic_list, methods=["GET", "POST"]),
        Route(prefix + "/{name}", dynamic, methods=["GET", "PUT", "DELETE"]),
        Route(prefix + "/{name}/logs", logs),
        Route(prefix + "/{name}/source", source),
        Route(prefix + "/{name}/files", files, methods=["GET", "POST"]),
        Route(prefix + "/{name}/files/{path:path}", files, methods=["GET", "DELETE"]),
        Route(prefix + "/{name}/commit", files, methods=["POST"]),
        Route(prefix + "/{name}/env", env, methods=["GET", "POST", "PATCH"]),
        Route(prefix + "/{name}/env/values", env),
        Route(prefix + "/{name}/user-env-fields", user_env),
        Route(prefix + "/{name}/policy", policy, methods=["GET", "POST"]),
        Route(prefix + "/{name}/{action}", lifecycle, methods=["POST"]),
    ]
