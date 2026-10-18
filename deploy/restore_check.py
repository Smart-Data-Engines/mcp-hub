"""Run only in the disposable recovery container, without a Docker socket.

The fixed hostname belongs to a newly created, isolated recovery network. Never
load the production STORE_URL or start a gateway during a recovery drill.
"""

import asyncio
import base64
import json
import time
from pathlib import Path

from dotenv import dotenv_values
from redis.asyncio import Redis

from mcp_hub.cli import import_state
from mcp_hub.config import Settings
from mcp_hub.security import Cipher


async def check() -> None:
    snapshot = json.loads(await asyncio.to_thread(Path("/recovery/redis-state.json").read_text))
    settings = Settings(store_url="redis://restore-store:6379/0", store_prefix=snapshot["prefix"])
    key = dotenv_values("/run/recovery.env")["CREDENTIALS_ENCRYPTION_KEY"]
    assert key
    cipher = Cipher(key)
    age = max(0, int(time.time() * 1000) - snapshot["created_at_ms"])
    count = await import_state(settings, snapshot)
    permanent, decrypted = 0, 0
    async with Redis.from_url(settings.store_url, decode_responses=False) as redis:
        for item in snapshot["entries"]:
            suffix = item["key"][len(settings.store_prefix) :]
            assert not suffix.startswith(
                ("oauth:access:", "oauth:refresh:", "oauth:principal:", "oauth:ui:")
            )
            if item["ttl_ms"] == -1:
                # Compare native payloads against the producer, rather than
                # serializing through the same application reader twice.
                assert await redis.dump(item["key"]) == base64.b64decode(item["dump"])
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
                "encrypted_records_decrypted": decrypted,
                "production_connections": 0,
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(check())
