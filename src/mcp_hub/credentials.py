"""Encrypted secrets and server-enforced resolution policies."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from redis.exceptions import RedisError

from .models import RESERVED_ARGS, HubError, Principal
from .security import Cipher
from .store import Store


@dataclass(slots=True)
class Resolved:
    credentials: dict[str, Any]
    source: str


class Credentials:
    def __init__(self, store: Store, cipher: Cipher):
        self.store, self.cipher = store, cipher

    async def save(
        self,
        principal_id: str,
        service: str,
        credentials: dict[str, Any],
        *,
        only_mine: bool | None = None,
    ) -> None:
        clean = {key: value for key, value in credentials.items() if key not in RESERVED_ARGS}
        if not clean or not any(value is not None and value != "" for value in clean.values()):
            raise HubError(
                "Provide non-empty personal credentials; hub identity fields are reserved", 422
            )
        encrypted = self.cipher.encrypt(clean)
        async with self.store.redis.pipeline(transaction=True) as pipeline:
            pipeline.set(self.store.key(f"creds:{principal_id}:{service}"), encrypted)
            pipeline.sadd(self.store.key(f"creds:{principal_id}:_index"), service)
            if only_mine is not None:
                pipeline.hset(
                    self.store.key(f"creds:{principal_id}:modes"),
                    service,
                    "1" if only_mine else "0",
                )
            await pipeline.execute()

    async def delete(self, principal_id: str, service: str) -> None:
        async with self.store.redis.pipeline(transaction=True) as pipeline:
            pipeline.delete(self.store.key(f"creds:{principal_id}:{service}"))
            pipeline.srem(self.store.key(f"creds:{principal_id}:_index"), service)
            await pipeline.execute()

    async def services(self, principal_id: str) -> list[str]:
        return sorted(
            await self.store.redis.smembers(self.store.key(f"creds:{principal_id}:_index"))
        )

    async def modes(self, principal_id: str) -> dict[str, bool]:
        values = await self.store.redis.hgetall(self.store.key(f"creds:{principal_id}:modes"))
        return {key: value == "1" for key, value in values.items()}

    async def set_mode(self, principal_id: str, service: str, only_mine: bool) -> None:
        await self.store.redis.hset(
            self.store.key(f"creds:{principal_id}:modes"), service, "1" if only_mine else "0"
        )

    async def resolve(
        self,
        principal: Principal,
        service: str,
        policy: str,
        header: str | None,
        required_fields: list[str] | None = None,
    ) -> Resolved:
        identity = (
            {
                "_hub_username": principal.username,
                "_hub_user_id": principal.id,
                "_hub_principal": principal.kind,
            }
            if principal.kind != "anonymous"
            else {}
        )
        if policy == "global_only" or principal.kind == "anonymous":
            if policy == "user_only" and principal.kind == "anonymous":
                raise HubError(
                    "This server requires personal credentials; sign in first",
                    403,
                    code="credentials_required",
                )
            if principal.kind != "anonymous":
                try:
                    async with asyncio.timeout(2):
                        only_mine = await self.store.redis.hget(
                            self.store.key(f"creds:{principal.id}:modes"), service
                        )
                except (TimeoutError, RedisError) as exc:
                    raise HubError(
                        "Personal credential preference cannot be verified",
                        503,
                        code="credentials_unavailable",
                    ) from exc
                if only_mine == "1":
                    raise HubError(
                        "This server requires global credentials, but you selected only personal credentials. Review your preference in the console before continuing.",
                        403,
                        code="credentials_required",
                    )
            return Resolved(identity, "none")
        supplied: dict[str, Any] | None = None
        if header:
            try:
                values = json.loads(header)
                supplied = values.get(service) if isinstance(values, dict) else None
                if supplied is not None and not isinstance(supplied, dict):
                    raise ValueError
            except (ValueError, TypeError) as exc:
                raise HubError(
                    "X-Hub-Credentials must be a JSON object of service objects", 400
                ) from exc
        if supplied:
            clean = {key: value for key, value in supplied.items() if key not in RESERVED_ARGS}
            if clean and any(value is not None and value != "" for value in clean.values()):
                self._complete(service, clean, required_fields or [])
                return Resolved({**clean, **identity}, "session_metadata")
        # Reading mode and secret together prevents a partial fallback that violates "only mine".
        try:
            async with asyncio.timeout(2):
                async with self.store.redis.pipeline(transaction=True) as pipeline:
                    pipeline.get(self.store.key(f"creds:{principal.id}:{service}"))
                    pipeline.hget(self.store.key(f"creds:{principal.id}:modes"), service)
                    encrypted, mode = await pipeline.execute()
        except (TimeoutError, ConnectionError, RedisError) as exc:
            raise HubError(
                "Credential store unavailable; personal credential policy cannot be verified",
                503,
                code="credentials_unavailable",
            ) from exc
        if encrypted:
            clean = {
                key: value
                for key, value in self.cipher.decrypt(encrypted).items()
                if key not in RESERVED_ARGS
            }
            if clean and any(value is not None and value != "" for value in clean.values()):
                self._complete(service, clean, required_fields or [])
                return Resolved({**clean, **identity}, "store")
        if policy == "user_only" or mode == "1":
            raise HubError(
                f"Add your own credentials for {service} in the panel before calling this tool",
                403,
                code="credentials_required",
            )
        return Resolved(identity, "none")

    @staticmethod
    def _complete(service: str, value: dict[str, Any], fields: list[str]) -> None:
        if any(
            field not in value or value[field] is None or value[field] == "" for field in fields
        ):
            raise HubError(
                f"Personal credentials for {service} are incomplete. Fill all declared User Env fields; global credentials will not be substituted silently.",
                403,
                code="credentials_required",
            )

    async def global_env(self, server: str, *, running: bool = False) -> dict[str, str]:
        async with asyncio.timeout(2):
            if running:
                snapshots = await self.store.redis.mget(
                    [
                        self.store.key("mcp:running-env:" + server),
                        self.store.key("mcp:env:" + server),
                    ]
                )
                encrypted = snapshots[0] or snapshots[1]
            else:
                encrypted = await self.store.redis.get(self.store.key("mcp:env:" + server))
        return self.cipher.decrypt(encrypted) if encrypted else {}

    async def save_global_env(self, server: str, values: dict[str, str]) -> None:
        await self.store.redis.set(self.store.key("mcp:env:" + server), self.cipher.encrypt(values))

    async def patch_global_env(
        self, server: str, values: dict[str, str], remove: list[str]
    ) -> None:
        """Change only submitted fields, preserving concurrent edits to other fields."""
        key = self.store.key("mcp:env:" + server)
        for _ in range(8):
            original = await self.store.redis.get(key)
            merged = self.cipher.decrypt(original) if original else {}
            for name in remove:
                merged.pop(name, None)
            merged.update(values)
            if await self.store.redis.eval(
                "if (redis.call('GET', KEYS[1]) or '') ~= ARGV[1] then return 0 end "
                "redis.call('SET', KEYS[1], ARGV[2]); return 1",
                1,
                key,
                original or "",
                self.cipher.encrypt(merged),
            ):
                return
        raise HubError("The connection changed concurrently. Try saving again.", 409)
