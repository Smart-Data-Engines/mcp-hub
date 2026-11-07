"""Run only in the disposable recovery container, without a Docker socket.

The fixed hostname belongs to a newly created, isolated recovery network. Never
load the production STORE_URL or start a gateway during a recovery drill.
"""

import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values
from redis.asyncio import Redis

from mcp_hub.cli import import_state
from mcp_hub.config import Settings
from mcp_hub.security import Cipher


async def verify_permanent_payload(
    redis: Redis, oracle: Redis, key: str, payload: bytes
) -> Literal["dump", "unordered"]:
    if await redis.dump(key) == payload:
        return "dump"
    kind = await redis.type(key)
    # Redis hash tables may serialize fields/members in a different order after
    # RESTORE. Compare exact native values against an independent native RESTORE
    # in another database of this disposable Redis, without application readers.
    assert kind in (b"hash", b"set"), "Restored payload differs from snapshot"
    await oracle.restore(key, 0, payload)
    try:
        assert await oracle.type(key) == kind, "Restored Redis type differs from snapshot"
        if kind == b"hash":
            assert await redis.hgetall(key) == await oracle.hgetall(key), (
                "Restored hash differs from snapshot"
            )
        else:
            assert await redis.smembers(key) == await oracle.smembers(key), (
                "Restored set differs from snapshot"
            )
    finally:
        await oracle.delete(key)
    return "unordered"


async def check() -> None:
    snapshot = json.loads(await asyncio.to_thread(Path("/recovery/redis-state.json").read_text))
    settings = Settings(store_url="redis://restore-store:6379/0", store_prefix=snapshot["prefix"])
    key = dotenv_values("/run/recovery.env")["CREDENTIALS_ENCRYPTION_KEY"]
    assert key
    cipher = Cipher(key)
    age = max(0, int(time.time() * 1000) - snapshot["created_at_ms"])
    count = await import_state(settings, snapshot)
    permanent, decrypted, unordered = 0, 0, 0
    async with (
        Redis.from_url(settings.store_url, decode_responses=False) as redis,
        Redis.from_url("redis://restore-store:6379/1", decode_responses=False) as oracle,
    ):
        for item in snapshot["entries"]:
            suffix = item["key"][len(settings.store_prefix) :]
            assert not suffix.startswith(
                ("oauth:access:", "oauth:refresh:", "oauth:principal:", "oauth:ui:")
            )
            if item["ttl_ms"] == -1:
                mode = await verify_permanent_payload(
                    redis, oracle, item["key"], base64.b64decode(item["dump"], validate=True)
                )
                unordered += mode == "unordered"
                assert await redis.pttl(item["key"]) == -1
                permanent += 1
            elif item["ttl_ms"] > age + 10_000:
                ttl = await redis.pttl(item["key"])
                assert 0 < ttl <= item["ttl_ms"] - age
            if suffix.startswith(("mcp:env:", "mcp:running-env:", "creds:")) and (
                await redis.type(item["key"]) == b"string"
            ):
                value = await redis.get(item["key"])
                assert value
                cipher.decrypt(value.decode())
                decrypted += 1
    assert count > 0 and permanent > 0, "An empty snapshot is not a recovery proof"
    print(
        json.dumps(
            {
                "restored_keys": count,
                "exact_permanent_payloads": permanent,
                "unordered_native_payloads_verified": unordered,
                "encrypted_records_decrypted": decrypted,
                "production_connections": 0,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(check())
