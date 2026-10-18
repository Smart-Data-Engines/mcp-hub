"""Operator commands. Secrets are accepted from the environment, never CLI arguments."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import signal
import time
from collections.abc import Awaitable
from pathlib import Path
from typing import Any, cast

import typer
import uvicorn
from redis.asyncio import Redis

from .acl import ACL
from .app import Hub, create_app, create_registration_app
from .config import Settings
from .models import Principal, ServerDefinition
from .security import Cipher, configure_logging
from .state_client import async_state
from .store import Store, digest, dumps

cli = typer.Typer(
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
    help="MCP Hub gateway and operator tools",
)


class Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self):
        # The two listeners share one lifecycle and one signal handler below.
        yield


async def serve(settings: Settings) -> None:
    app = create_app(settings)
    hub = app.state.hub
    control = Server(
        uvicorn.Config(
            app,
            host=settings.hub_bind_host,
            port=settings.hub_port,
            log_config=None,
            access_log=False,
            proxy_headers=bool(settings.trusted_proxy_ips),
            forwarded_allow_ips=settings.trusted_proxy_ips,
            timeout_graceful_shutdown=int(settings.shutdown_grace_period),
        )
    )
    registration = Server(
        uvicorn.Config(
            create_registration_app(hub),
            host="0.0.0.0",
            port=settings.registration_port,
            lifespan="off",
            log_config=None,
            access_log=False,
            proxy_headers=False,
        )
    )
    closing: asyncio.Task | None = None

    async def shutdown() -> None:
        # This assignment precedes the first await, so readiness changes on the signal tick.
        hub.ready, hub.gateway.draining = False, True
        await hub.drain()
        control.should_exit = registration.should_exit = True

    def stopped() -> None:
        nonlocal closing
        hub.ready, hub.gateway.draining = False, True
        if closing is None:
            closing = asyncio.create_task(shutdown())

    loop = asyncio.get_running_loop()
    for name in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(name, stopped)
    tasks = [asyncio.create_task(control.serve()), asyncio.create_task(registration.serve())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stopped()
        if closing:
            await closing
        await asyncio.gather(*tasks, return_exceptions=True)


@cli.command("serve")
def serve_command() -> None:
    """Run the public control listener and registration-only listener."""
    configure_logging()
    asyncio.run(serve(Settings.from_env()))


@cli.command()
def bootstrap_admin(subject: str, username: str) -> None:
    """Provision the first administrator by their verified OIDC subject (sub)."""
    settings = Settings.from_env()
    if settings.admin_emails:
        raise typer.BadParameter(
            "ADMIN_EMAILS manages administrators; sign in with a verified allowed company account"
        )
    if not settings.idp_issuer:
        raise typer.BadParameter("IDP_ISSUER must be configured")
    principal = Principal(
        id="user_" + digest(settings.idp_issuer + "\0" + subject), username=username
    )

    async def run() -> None:
        async with Redis.from_url(settings.store_url, decode_responses=True) as redis:
            store = Store(redis, settings.store_prefix)
            acl = ACL(store)
            await acl.initialize()
            await acl.provision(principal)
            await store.redis.sadd(store.key("acl:admins"), principal.id)

    asyncio.run(run())
    typer.echo("Administrator provisioned: " + principal.id)


@cli.command()
def seed_demo() -> None:
    """Create two read-only sample adapters in the local development registry."""
    settings = Settings.from_env()
    if settings.environment != "development" or settings.registry_backend != "local":
        raise typer.BadParameter("Demo seeding requires development mode and the local registry")

    async def run() -> None:
        hub = Hub(settings)
        await hub.start(background=False)
        try:
            for name, entries in {
                "demo-directory": ["Engineering", "Operations", "Research"],
                "demo-notes": [
                    "Connect your MCP client to /mcp",
                    "Your identity controls which tools are available",
                    "Create an adapter in My MCP servers",
                ],
            }.items():
                existing = (await hub.store.dynamic()).get(name)
                if existing and existing["owner"] != "_official":
                    raise ValueError("A demo name is already owned by another principal")
                if not existing:
                    definition = ServerDefinition(
                        name=name,
                        owner="_official",
                        visibility="public",
                        autostart=True,
                        description="Local demonstration data; read-only adapter",
                    )
                    await hub.runtime.create(definition)
                    code = '''import os
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from mcp_hub.upstream import serve
mcp=FastMCP(os.environ['SERVER_NAME'],stateless_http=True,json_response=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
ENTRIES = SAMPLE_ENTRIES
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True,destructiveHint=False,idempotentHint=True))
async def search(query:str='',credentials:dict|None=None)->dict:
    """Search this adapter's local demonstration data; makes no external requests."""
    caller=(credentials or {}).get('_hub_username')
    if not caller:raise ValueError('An authenticated caller is required')
    return {'entries':[entry for entry in ENTRIES if query.casefold() in entry.casefold()],
        'source':os.environ['SERVER_NAME'],'caller':caller}
if __name__=='__main__':serve(mcp)
'''.replace("SAMPLE_ENTRIES", repr(entries))
                    await hub.registry.commit(
                        f"_official/{name}",
                        {"server.py": code},
                        "Publish local demonstration adapter",
                    )
                if not existing or existing.get("status") != "running":
                    await hub.runtime.start(name, restart=True)
            await hub.store.script(
                """
                local raw=redis.call('HGET',KEYS[1],'default')
                local group=raw and cjson.decode(raw) or {servers={}}
                group.servers=group.servers or {}
                group.servers['demo-directory']={'read'}; group.servers['demo-notes']={'read'}
                redis.call('HSET',KEYS[1],'default',cjson.encode(group)); return 1
            """,
                ["acl:groups"],
            )
        finally:
            await hub.close()

    asyncio.run(run())
    typer.echo(
        "Read-only demo-directory and demo-notes adapters are available to the default group"
    )


@cli.command()
def rotate_key() -> None:
    """Re-encrypt credentials and Global Env using the first configured Fernet key."""
    settings = Settings.from_env()
    cipher = Cipher(settings.credentials_encryption_key)

    async def run() -> int:
        count = 0
        async with Redis.from_url(settings.store_url, decode_responses=True) as native:
            redis = async_state(native)
            for namespace in ("creds:", "mcp:env:", "mcp:running-env:", "idp:token:"):
                async for key in redis.scan_iter(match=settings.store_prefix + namespace + "*"):
                    if await redis.type(key) != "string":
                        continue
                    raw = await redis.get(key)
                    if raw is None:
                        continue
                    rotated = cipher.rotate(raw)
                    # CAS preserves a concurrently updated credential and its TTL.
                    changed = await redis.eval(
                        "if redis.call('GET',KEYS[1])==ARGV[1] then redis.call('SET',KEYS[1],ARGV[2],'KEEPTTL'); return 1 end return 0",
                        1,
                        key,
                        raw,
                        rotated,
                    )
                    count += int(changed)
        return count

    typer.echo(
        f"Re-encrypted {asyncio.run(run())} values; keep old keys until every replica is updated"
    )


async def export_state(settings: Settings) -> dict:
    """One atomic native Redis snapshot; intended as an offline maintenance operation."""
    created_at_ms = int(time.time() * 1000)
    async with Redis.from_url(settings.store_url, decode_responses=False) as redis:
        values = await cast(
            Awaitable[Any],
            redis.eval(
                """
            local result={}
            for _,key in ipairs(redis.call('KEYS',ARGV[1]..'*')) do
                table.insert(result,key); table.insert(result,redis.call('DUMP',key)); table.insert(result,redis.call('PTTL',key))
            end
            return result
        """,
                0,
                settings.store_prefix,
            ),
        )
    entries = [
        {
            "key": values[i].decode(),
            "dump": base64.b64encode(values[i + 1]).decode(),
            "ttl_ms": int(values[i + 2]),
        }
        for i in range(0, len(values), 3)
        if not values[i]
        .decode()[len(settings.store_prefix) :]
        .startswith(
            (
                "oauth:access:",
                "oauth:refresh:",
                "oauth:principal:",
                "oauth:code:",
                "oauth:state:",
                "oauth:ui:",
                "oauth:consent:",
            )
        )
    ]
    return {
        "format": "mcp-hub-redis-dump-v1",
        "prefix": settings.store_prefix,
        "created_at_ms": created_at_ms,
        "entries": entries,
    }


async def import_state(settings: Settings, snapshot: dict) -> int:
    if (
        snapshot.get("format") != "mcp-hub-redis-dump-v1"
        or snapshot.get("prefix") != settings.store_prefix
    ):
        raise ValueError("Backup format or namespace does not match this installation")
    entries = snapshot["entries"]
    age_ms = max(0, int(time.time() * 1000) - int(snapshot.get("created_at_ms", 0)))
    restored = 0
    if any(not item["key"].startswith(settings.store_prefix) for item in entries):
        raise ValueError("Backup contains keys outside the configured namespace")
    async with Redis.from_url(settings.store_url, decode_responses=False) as redis:
        keys = await redis.keys(settings.store_prefix + "*")
        if keys:
            raise ValueError("Restore requires an empty namespace and stopped gateway replicas")
        async with redis.pipeline(transaction=True) as pipeline:
            for entry in entries:
                ttl = entry["ttl_ms"]
                if ttl == -2:
                    continue
                if ttl >= 0:
                    ttl -= age_ms
                    if ttl <= 0:
                        continue
                pipeline.restore(
                    entry["key"],
                    max(0, ttl),
                    base64.b64decode(entry["dump"], validate=True),
                    replace=False,
                )
                restored += 1
            await pipeline.execute()
    return restored


@cli.command()
def backup(output: Path) -> None:
    """Export an atomic maintenance snapshot; the output contains sensitive state."""
    settings = Settings.from_env()
    snapshot = asyncio.run(export_state(settings))
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(dumps(snapshot))
    typer.echo(f"Saved {len(snapshot['entries'])} state keys to {output}")


@cli.command()
def restore(source: Path) -> None:
    """Restore into an empty namespace with the gateways stopped."""
    settings = Settings.from_env()
    count = asyncio.run(import_state(settings, json.loads(source.read_text())))
    typer.echo(f"Restored {count} keys; verify ACL and server counts before starting the gateway")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
