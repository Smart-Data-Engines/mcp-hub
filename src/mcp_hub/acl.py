"""One atomic permission snapshot per request; no per-principal cache."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .models import ALL_CAPS, Category, HubError, Principal, visible
from .store import Store, dumps


@dataclass(slots=True)
class Access:
    principal: Principal
    user: dict[str, Any]
    group: dict[str, Any]
    definitions: dict[str, Any]
    admin: bool
    manager: bool

    def capabilities(self, server: str) -> set[Category]:
        definition = self.definitions.get(server, {})
        if not visible(definition, self.principal, admin=self.admin):
            return set()
        if self.admin or definition.get("owner") == self.principal.id:
            return ALL_CAPS.copy()
        grants = self.user.get("grants", {})
        group_servers = self.group.get("servers", {})
        if server not in grants and (
            server in self.user.get("denies", []) or server not in group_servers
        ):
            return set()
        return set(group_servers.get(server, [])) | set(grants.get(server, []))

    def permits(self, server: str, category: Category) -> bool:
        return category in self.capabilities(server)

    def sources(self, server: str) -> dict[str, Any]:
        return {
            "group": self.user.get("group", "default"),
            "group_caps": list(self.group.get("servers", {}).get(server) or []),
            "personal_grant": list(self.user["grants"][server] or [])
            if server in self.user.get("grants", {})
            else None,
            "personal_deny": server in self.user.get("denies", []),
            "owner": self.definitions.get(server, {}).get("owner") == self.principal.id,
            "admin": self.admin,
            "visibility": self.definitions.get(server, {}).get("visibility", "public"),
            "visible": visible(self.definitions.get(server, {}), self.principal, admin=self.admin),
            "effective_caps": sorted(self.capabilities(server)),
        }


class ACL:
    def __init__(self, store: Store):
        self.store = store

    async def initialize(self) -> None:
        for group in ("default", "_bots"):
            await self.store.redis.hsetnx(
                self.store.key("acl:groups"),
                group,
                dumps({"servers": {}, "approval_required": False}),
            )

    async def provision(self, principal: Principal) -> None:
        value = {
            **principal.model_dump(),
            "group": "_bots" if principal.kind == "bot" else "default",
            "grants": {},
            "denies": [],
        }
        await self.store.redis.hsetnx(self.store.key("acl:users"), principal.id, dumps(value))

    async def apply_admin_policy(
        self, emails: str, *, principal: Principal | None = None, verified_email: str = ""
    ) -> None:
        """Operator-managed administrators are bound only to verified OIDC email claims."""
        if not emails:
            return
        await self.store.script(
            """
            local allowed=cjson.decode(ARGV[1])
            if ARGV[2]~='' then
                local bindings=redis.call('HGETALL',KEYS[1])
                for i=1,#bindings,2 do
                    if bindings[i+1]==ARGV[2] then redis.call('HDEL',KEYS[1],bindings[i]) end
                end
                for _,email in ipairs(allowed) do if email==ARGV[3] then
                    redis.call('HSET',KEYS[1],email,ARGV[2]) end end
            end
            redis.call('DEL',KEYS[2])
            for _,email in ipairs(allowed) do
                local id=redis.call('HGET',KEYS[1],email)
                if id then
                    local raw=redis.call('HGET',KEYS[3],id)
                    if raw and cjson.decode(raw).kind=='human' then redis.call('SADD',KEYS[2],id) end
                end
            end
            return 1
            """,
            ["acl:verified-admins", "acl:admins", "acl:users"],
            [
                dumps(sorted({email.strip().lower() for email in emails.split(",")})),
                principal.id if principal else "",
                verified_email.lower(),
            ],
        )

    async def snapshot(self, principal: Principal) -> Access:
        raw = await self.store.script(
            """
            local user=redis.call('HGET',KEYS[1],ARGV[1]) or ARGV[2]
            local group=redis.call('HGET',KEYS[2],cjson.decode(user).group) or ARGV[3]
            return {user,group,redis.call('SISMEMBER',KEYS[3],ARGV[1]),
                redis.call('SISMEMBER',KEYS[4],ARGV[1]),redis.call('HGETALL',KEYS[5])}
        """,
            ["acl:users", "acl:groups", "acl:admins", "acl:managers", "acl:visibility"],
            [
                principal.id,
                dumps(
                    {
                        "group": "_bots" if principal.kind == "bot" else "default",
                        "grants": {},
                        "denies": [],
                    }
                ),
                dumps({"servers": {}}),
            ],
        )
        data = {
            "user": json.loads(raw[0]),
            "group": json.loads(raw[1]),
            "admin": bool(raw[2]),
            "manager": bool(raw[3]),
            "definitions": {
                raw[4][index]: json.loads(raw[4][index + 1]) for index in range(0, len(raw[4]), 2)
            },
        }
        data["user"]["grants"] = data["user"].get("grants") or {}
        data["group"]["servers"] = data["group"].get("servers") or {}
        if principal.kind == "anonymous":
            data["user"] = {"group": "default", "grants": {}, "denies": []}
            data["admin"] = data["manager"] = False
        return Access(principal=principal, **data)

    async def change_user(self, user_id: str, operation: str, payload: Any) -> None:
        result = await self.store.script(
            """
            local raw=redis.call('HGET',KEYS[1],ARGV[1]); if not raw then return 0 end
            local u=cjson.decode(raw); local p=cjson.decode(ARGV[3])
            if ARGV[2]=='group' then
                if redis.call('HEXISTS',KEYS[2],p)==0 then return -1 end; u.group=p
            elseif ARGV[2]=='grant' then u.grants[p.server]=p.caps
            elseif ARGV[2]=='ungrant' then u.grants[p]=nil
            elseif ARGV[2]=='deny' then
                local found=false; for _,v in ipairs(u.denies) do if v==p then found=true end end
                if not found then table.insert(u.denies,p) end
            elseif ARGV[2]=='undeny' then
                local d={}; for _,v in ipairs(u.denies) do if v~=p then table.insert(d,v) end end; u.denies=d
            end
            redis.call('HSET',KEYS[1],ARGV[1],cjson.encode(u)); return 1
        """,
            ["acl:users", "acl:groups"],
            [user_id, operation, dumps(payload)],
        )
        if result != 1:
            raise HubError("User or group not found", 404)

    async def directory(self) -> list[Access]:
        """Read people, roles, groups and visibility from one coherent snapshot."""
        raw = await self.store.script(
            """
            return {redis.call('HGETALL',KEYS[1]),redis.call('HGETALL',KEYS[2]),
                redis.call('SMEMBERS',KEYS[3]),redis.call('SMEMBERS',KEYS[4]),
                redis.call('HGETALL',KEYS[5])}
            """,
            ["acl:users", "acl:groups", "acl:admins", "acl:managers", "acl:visibility"],
        )

        def mapping(items):
            return {items[i]: json.loads(items[i + 1]) for i in range(0, len(items), 2)}

        users, groups, definitions = mapping(raw[0]), mapping(raw[1]), mapping(raw[4])
        result = []
        for user in users.values():
            user["grants"] = user.get("grants") or {}
            user["denies"] = user.get("denies") or []
            group = groups.get(user["group"], {"servers": {}})
            group["servers"] = group.get("servers") or {}
            result.append(
                Access(
                    principal=Principal.model_validate(user),
                    user=user,
                    group=group,
                    definitions=definitions,
                    admin=user["id"] in raw[2],
                    manager=user["id"] in raw[3],
                )
            )
        return result

    async def set_server_access(
        self, actor: Principal, user_id: str, server: str, mode: str, capabilities: list[str]
    ) -> None:
        """Change a person's rule and any required sharing in one transaction.

        Granting to one person never opens the server to the whole organization.
        Recheck roles inside the transaction and preserve concurrent lifecycle updates.
        """
        result = await self.store.script(
            """
            local admin=redis.call('SISMEMBER',KEYS[2],ARGV[1])==1
            if not admin and redis.call('SISMEMBER',KEYS[3],ARGV[1])==0 then return -1 end
            local target_admin=redis.call('SISMEMBER',KEYS[2],ARGV[2])==1
            if not admin and (ARGV[1]==ARGV[2] or target_admin) then return -2 end
            local raw=redis.call('HGET',KEYS[1],ARGV[2]); if not raw then return -3 end
            local server_raw=redis.call('HGET',KEYS[4],ARGV[3])
            local catalog=cjson.decode(redis.call('GET',KEYS[7]) or '{"servers":{}}')
            if not server_raw and not catalog.servers[ARGV[3]] then return -4 end
            local u=cjson.decode(raw)
            local definition=server_raw and cjson.decode(server_raw) or {visibility='public'}
            if target_admin or definition.owner==ARGV[2] then return -5 end
            local group=cjson.decode(redis.call('HGET',KEYS[8],u.group) or '{"servers":{}}')
            local inherited=group.servers and group.servers[ARGV[3]] or {}
            local granting=ARGV[4]=='grant' or (ARGV[4]=='inherit' and #inherited>0)
            local shared=false
            for _,id in ipairs(definition.shared_with or {}) do if id==ARGV[2] then shared=true end end
            local hidden=definition.visibility~='public' and not (definition.visibility=='shared' and shared)
            if granting and hidden then
                if not admin then return -6 end
                if definition.visibility=='private' then definition.shared_with={}; shared=false end
                if not shared and #(definition.shared_with or {})>=100 then return -7 end
                definition.visibility='shared'
                definition.shared_with=definition.shared_with or {}
                if not shared then table.insert(definition.shared_with,ARGV[2]) end
                local encoded=cjson.encode(definition)
                redis.call('HSET',KEYS[4],ARGV[3],encoded)
                redis.call('HSET',KEYS[5],ARGV[3],encoded)
                redis.call('INCR',KEYS[6])
            end
            u.grants=u.grants or {}
            u.grants[ARGV[3]]=nil
            local denies={}
            for _,name in ipairs(u.denies or {}) do if name~=ARGV[3] then table.insert(denies,name) end end
            if ARGV[4]=='block' then table.insert(denies,ARGV[3])
            elseif ARGV[4]=='grant' then u.grants[ARGV[3]]=cjson.decode(ARGV[5]) end
            u.denies=denies
            redis.call('HSET',KEYS[1],ARGV[2],cjson.encode(u))
            return 1
            """,
            [
                "acl:users",
                "acl:admins",
                "acl:managers",
                "mcp:dynamic",
                "acl:visibility",
                "mcp:registry:generation",
                "mcp:catalog",
                "acl:groups",
            ],
            [actor.id, user_id, server, mode, dumps(capabilities)],
        )
        errors = {
            -1: ("Administrator or manager role required", 403),
            -2: ("Managers cannot change their own or administrators' access", 403),
            -3: ("User not found", 404),
            -4: ("Server not found. Refresh the server list and try again.", 404),
            -5: (
                "Owners and administrators always have full access. Change ownership or role first.",
                409,
            ),
            -6: (
                "This server is restricted. Ask an administrator to share it with this person first.",
                409,
            ),
            -7: (
                "This server already has 100 selected people. Review its audience before adding another person.",
                409,
            ),
        }
        if result != 1:
            message, status = errors.get(result, ("Access could not be saved", 409))
            raise HubError(message, status)

    async def remove_admin(self, user_id: str) -> None:
        result = await self.store.script(
            """
            if redis.call('SISMEMBER',KEYS[1],ARGV[1])==1 and redis.call('SCARD',KEYS[1])<=1 then return 0 end
            redis.call('SREM',KEYS[1],ARGV[1]); return 1
        """,
            ["acl:admins"],
            [user_id],
        )
        if not result:
            raise HubError("The last administrator cannot be removed", 409)

    async def delete_group(self, name: str) -> None:
        if name in {"default", "_bots"}:
            raise HubError("Built-in groups cannot be removed", 409)
        await self.store.script(
            """
            local users=redis.call('HGETALL',KEYS[1])
            for i=1,#users,2 do local u=cjson.decode(users[i+1]); if u.group==ARGV[1] then
                u.group=u.kind=='bot' and '_bots' or 'default'; redis.call('HSET',KEYS[1],users[i],cjson.encode(u)) end end
            return redis.call('HDEL',KEYS[2],ARGV[1])
        """,
            ["acl:users", "acl:groups"],
            [name],
        )
