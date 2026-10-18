"""Redis state. Security-sensitive transitions execute as single Lua operations.

Redis Cluster is intentionally unsupported: reverse-index operations address keys
on one durable Redis primary. Gateway replicas share that primary.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from redis.asyncio import Redis

from .state_client import StateClient, async_state


def dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, redis: Redis | StateClient, prefix: str = "hub:v1:"):
        self.redis, self.prefix = async_state(redis), prefix

    def key(self, suffix: str) -> str:
        return self.prefix + suffix

    async def script(self, source: str, keys: list[str], args: list[Any] | None = None) -> Any:
        return await self.redis.eval(source, len(keys), *(self.key(k) for k in keys), *(args or []))

    async def get(self, key: str, default: Any = None) -> Any:
        value = await self.redis.get(self.key(key))
        return json.loads(value) if value is not None else default

    async def put(self, key: str, value: Any, *, ttl: int | None = None, nx: bool = False) -> bool:
        return bool(await self.redis.set(self.key(key), dumps(value), ex=ttl, nx=nx))

    async def delete(self, key: str) -> None:
        await self.redis.delete(self.key(key))

    async def unlock(self, key: str, owner: str) -> None:
        await self.script(
            "if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
            [key],
            [dumps(owner)],
        )

    async def rate(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        if not limit:
            return True, 0
        value = await self.script(
            """
            local n=tonumber(redis.call('GET',KEYS[1]) or '0')
            if n>=tonumber(ARGV[1]) then return {0,redis.call('TTL',KEYS[1])} end
            n=redis.call('INCR',KEYS[1])
            if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[2]) end
            return {1,redis.call('TTL',KEYS[1])}
        """,
            ["ratelimit:" + key],
            [limit, window],
        )
        return bool(value[0]), max(1, int(value[1]))

    async def catalog(self) -> dict[str, Any]:
        value = await self.get("mcp:catalog", {"version": 0, "servers": {}})
        value["servers"] = value.get("servers") or {}
        return value

    async def publish_catalog(
        self, servers: dict[str, Any], *, generation: int | None = None
    ) -> int:
        return int(
            await self.script(
                """
            if ARGV[2]~='-1' and tonumber(redis.call('GET',KEYS[4]) or '0')~=tonumber(ARGV[2]) then return -1 end
            local old=redis.call('GET',KEYS[3])
            local version=tonumber(redis.call('GET',KEYS[2]) or '0')
            if old==ARGV[1] then return version end
            version=redis.call('INCR',KEYS[2])
            redis.call('SET',KEYS[1],'{"version":'..version..',"servers":'..ARGV[1]..'}')
            redis.call('SET',KEYS[3],ARGV[1])
            return version
        """,
                [
                    "mcp:catalog",
                    "mcp:catalog:version",
                    "mcp:catalog:content",
                    "mcp:registry:generation",
                ],
                [dumps(servers), -1 if generation is None else generation],
            )
        )

    async def registered(self) -> dict[str, Any]:
        _, result = await self.registered_snapshot()
        return result

    async def registered_snapshot(self) -> tuple[int, dict[str, Any]]:
        result = await self.script(
            """
            local result={}
            for _,name in ipairs(redis.call('SMEMBERS',KEYS[1])) do
                local value=redis.call('GET',ARGV[1]..name)
                if value then table.insert(result,name); table.insert(result,value)
                else redis.call('SREM',KEYS[1],name); redis.call('INCR',KEYS[2]) end
            end
            return {tonumber(redis.call('GET',KEYS[2]) or '0'),result}
        """,
            ["mcp:registered:_index", "mcp:registry:generation"],
            [self.key("mcp:registered:")],
        )
        values = result[1]
        return int(result[0]), {
            values[index]: json.loads(values[index + 1]) for index in range(0, len(values), 2)
        }

    async def register(self, name: str, data: dict[str, Any], ttl: int) -> bool:
        return bool(
            await self.script(
                """
            local old=redis.call('GET',KEYS[1])
            local managed=redis.call('HGET',KEYS[4],ARGV[3])
            if managed then local status=cjson.decode(managed).status; if status=='stopped' or status=='stopping' or status=='error' then return 0 end end
            if old and cjson.decode(old).url~=cjson.decode(ARGV[1]).url then return 0 end
            if not old or cjson.decode(old).code_version~=cjson.decode(ARGV[1]).code_version then redis.call('INCR',KEYS[3]) end
            redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[2]); redis.call('SADD',KEYS[2],ARGV[3]); return 1
        """,
                [
                    "mcp:registered:" + name,
                    "mcp:registered:_index",
                    "mcp:registry:generation",
                    "mcp:dynamic",
                ],
                [dumps(data), ttl, name],
            )
        )

    async def unregister(self, name: str) -> None:
        await self.script(
            "redis.call('DEL',KEYS[1]); local removed=redis.call('SREM',KEYS[2],ARGV[1]); if removed>0 then redis.call('INCR',KEYS[3]) end; return removed",
            ["mcp:registered:" + name, "mcp:registered:_index", "mcp:registry:generation"],
            [name],
        )

    async def dynamic(self) -> dict[str, Any]:
        values = await self.redis.hgetall(self.key("mcp:dynamic"))
        return {k: json.loads(v) for k, v in values.items()}

    async def save_dynamic(
        self, name: str, value: dict[str, Any], *, create: bool = False, limit: int = 10
    ) -> int:
        return int(
            await self.script(
                """
            local old=redis.call('HGET',KEYS[1],ARGV[1]); local data=cjson.decode(ARGV[2])
            if ARGV[3]=='1' then
                if old or redis.call('EXISTS',KEYS[3])==1 then return -1 end
                local reserved=redis.call('HGET',KEYS[5],ARGV[1]); if reserved and reserved~=data.owner then return -1 end
                local count=0
                for _,v in ipairs(redis.call('HVALS',KEYS[1])) do if cjson.decode(v).owner==data.owner then count=count+1 end end
                if count>=tonumber(ARGV[4]) then return -2 end
            end
            redis.call('HSETNX',KEYS[5],ARGV[1],data.owner)
            redis.call('HSET',KEYS[1],ARGV[1],ARGV[2]); redis.call('HSET',KEYS[2],ARGV[1],ARGV[2]); redis.call('INCR',KEYS[4]); return 1
        """,
                [
                    "mcp:dynamic",
                    "acl:visibility",
                    "mcp:registered:" + name,
                    "mcp:registry:generation",
                    "mcp:reserved-names",
                ],
                [name, dumps(value), "1" if create else "0", limit],
            )
        )

    async def delete_dynamic(self, name: str) -> None:
        await self.script(
            "local old=redis.call('HGET',KEYS[1],ARGV[1]); if old then redis.call('HSETNX',KEYS[4],ARGV[1],cjson.decode(old).owner) end; redis.call('HDEL',KEYS[1],ARGV[1]); redis.call('INCR',KEYS[3]); return redis.call('HDEL',KEYS[2],ARGV[1])",
            ["mcp:dynamic", "acl:visibility", "mcp:registry:generation", "mcp:reserved-names"],
            [name],
        )

    async def patch_dynamic(self, name: str, changes: dict[str, Any]) -> dict[str, Any]:
        """CAS preserves lifecycle and policy updates made by different replicas."""
        for _ in range(10):
            raw = await self.redis.hget(self.key("mcp:dynamic"), name)
            if raw is None:
                raise ValueError("Server was removed concurrently")
            value = {**json.loads(raw), **changes}
            changed = await self.script(
                """
                if redis.call('HGET',KEYS[1],ARGV[1])~=ARGV[2] then return 0 end
                redis.call('HSET',KEYS[1],ARGV[1],ARGV[3]); redis.call('HSET',KEYS[2],ARGV[1],ARGV[3]);
                redis.call('INCR',KEYS[3]); return 1
            """,
                ["mcp:dynamic", "acl:visibility", "mcp:registry:generation"],
                [name, raw, dumps(value)],
            )
            if changed:
                return value
        raise ValueError("Server changed too frequently; retry the operation")
