"""ASGI composition. Public control and upstream registration use separate listeners."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import time
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, Tool
from redis.asyncio import Redis
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .acl import ACL
from .api import management_routes
from .config import Settings
from .credentials import Credentials
from .gateway import Gateway, request_context
from .http import Boundary, body, error_response, oauth_routes
from .models import HubError, Registration
from .oauth import OAuth, OAuthError
from .observability import Audit, Metrics
from .registry import GitHubRegistry, LocalGitRegistry, Registry, RemoteGitRegistry
from .runtime import Runtime, container_name, registration_secret
from .security import Cipher
from .state_client import async_state
from .store import Store
from .telemetry import configure as configure_telemetry
from .tls import trust
from .upstreams import Upstreams

log = logging.getLogger(__name__)


class Hub:
    def __init__(
        self,
        settings: Settings,
        redis: Redis | None = None,
        http_client: httpx.AsyncClient | None = None,
        registry: Registry | None = None,
    ):
        self.settings = settings
        self.own_redis, self.own_http = redis is None, http_client is None
        self.redis = async_state(
            redis
            if redis is not None
            else Redis.from_url(
                settings.store_url,
                decode_responses=True,
                socket_timeout=3,
                socket_connect_timeout=3,
            )
        )
        self.http = (
            http_client
            if http_client is not None
            else httpx.AsyncClient(
                trust_env=False,
                follow_redirects=False,
                verify=trust(settings.hub_ca_bundle),
                proxy=settings.hub_http_proxy or None,
            )
        )
        self.store = Store(self.redis, settings.store_prefix)
        self.acl, self.metrics = ACL(self.store), Metrics()
        self.credentials = Credentials(
            self.store,
            Cipher(settings.credentials_encryption_key),
            max_bytes=settings.max_credential_bytes,
            max_services=settings.max_credential_services,
            max_preferences=settings.max_credential_preferences,
        )
        self.oauth = OAuth(self.store, settings, self.acl, self.http)
        self.upstreams = Upstreams(self.store, settings, self.metrics)
        self.audit = Audit(self.store, settings, self.metrics, self.http)
        self.gateway = Gateway(
            self.store,
            settings,
            self.acl,
            self.credentials,
            self.upstreams,
            self.audit,
            self.metrics,
        )
        self.registry = registry or (
            LocalGitRegistry(
                settings.registry_local_path,
                settings.registry_branch,
                read_only=settings.registry_read_only,
            )
            if settings.registry_backend == "local"
            else RemoteGitRegistry(settings)
            if settings.registry_backend == "git"
            else GitHubRegistry(settings, self.http)
        )
        self.runtime = Runtime(
            self.store, settings, self.registry, self.credentials, self.upstreams
        )
        self.ready = False
        self._probe_lock = asyncio.Lock()
        self._probe_checked = 0.0
        self._probe_healthy = False
        self.upstreams.ensure_network = self.runtime.attach_network
        self.telemetry = configure_telemetry(settings.otel_exporter_otlp_endpoint)
        self.background: list[asyncio.Task[Any]] = []

    async def store_ready(self) -> bool:
        # Coalesce concurrent infrastructure probes; authorization/ACL stay uncached.
        if time.monotonic() - self._probe_checked >= 0.25:
            async with self._probe_lock:
                if time.monotonic() - self._probe_checked >= 0.25:
                    try:
                        self._probe_healthy = bool(await self.redis.ping())
                    except Exception:
                        self._probe_healthy = False
                    self._probe_checked = time.monotonic()
        return self._probe_healthy

    async def monitor(self) -> None:
        while True:
            try:
                info = await self.redis.info("memory")
                used, maximum = info.get("used_memory", 0), info.get("maxmemory", 0)
                self.metrics.memory.set(used)
                if maximum and used / maximum >= 0.8:
                    log.warning("Redis memory above 80%%: %d / %d bytes", used, maximum)
                totals: dict[str, int] = {}
                async for key in self.redis.scan_iter(match=self.store.prefix + "*", count=100):
                    namespace = key[len(self.store.prefix) :].partition(":")[0]
                    totals[namespace] = totals.get(namespace, 0) + int(
                        await self.redis.memory_usage(key) or 0
                    )
                for prefix, size in totals.items():
                    self.metrics.prefix_memory.labels(prefix).set(size)
            except Exception as exc:
                log.warning("Store monitoring unavailable: %s", type(exc).__name__)
            await asyncio.sleep(60)

    async def start(self, background: bool = True) -> None:
        await self.redis.ping()
        try:
            persistence = await self.redis.info("persistence")
            if not persistence.get("aof_enabled"):
                log.warning(
                    "Redis append-only persistence is disabled: ACL and credentials may be lost on restart"
                )
            policy = await self.redis.config_get("maxmemory-policy")
            if policy.get("maxmemory-policy") != "noeviction":
                raise HubError("Redis must use maxmemory-policy noeviction", 503)
        except HubError:
            raise
        except Exception as exc:
            log.warning("Cannot verify Redis durability settings: %s", type(exc).__name__)
        await self.acl.initialize()
        await self.acl.apply_admin_policy(self.settings.admin_emails)
        await self.oauth.initialize()
        await self.runtime.verify()
        await self.runtime.reconnect_running()
        for _ in range(20):
            if await self.upstreams.refresh():
                break
        else:
            raise HubError(
                "Registry kept changing during startup; readiness was not published", 503
            )
        self.ready = True
        if background:
            self.background = [
                asyncio.create_task(self.upstreams.run()),
                asyncio.create_task(self.audit.run()),
                asyncio.create_task(self.monitor()),
                asyncio.create_task(self.runtime.resume()),
            ]

    async def drain(self) -> None:
        self.ready, self.gateway.draining = False, True
        pending = {task for task in self.gateway.tasks if not task.done()}
        if pending:
            _, unfinished = await asyncio.wait(pending, timeout=self.settings.shutdown_grace_period)
            for task in unfinished:
                task.cancel()
            await asyncio.gather(*unfinished, return_exceptions=True)

    async def close(self) -> None:
        await self.drain()
        for task in self.background:
            task.cancel()
        await asyncio.gather(*self.background, return_exceptions=True)
        await self.upstreams.close()
        with contextlib.suppress(Exception):
            await self.audit.flush()
        if self.runtime.client:
            await asyncio.to_thread(self.runtime.client.close)
        if self.own_http:
            await self.http.aclose()
        if self.own_redis:
            await self.redis.aclose()
        if self.telemetry:
            await asyncio.to_thread(self.telemetry.force_flush, timeout_millis=2000)


def _registration_routes(hub: Hub) -> list[Route]:
    async def authenticate(request: Request, payload: dict[str, Any]) -> None:
        name = payload.get("name", "")
        definition = (await hub.store.dynamic()).get(name)
        supplied = request.headers.get("x-hub-secret", "")
        master = hub.settings.hub_registration_secret
        expected = registration_secret(master, name) if definition and master else master
        if not expected and not hub.settings.hub_allow_insecure_registration:
            raise HubError("Registration is disabled until a secret is configured", 403)
        if expected and not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise HubError("Invalid registration secret", 403)
        if definition and "url" in payload:
            if definition["status"] not in {"starting", "running"}:
                raise HubError(
                    "Managed server registration is disabled while stopped or stopping", 403
                )
            if payload["url"] != f"http://{container_name(name)}:3000/mcp":
                raise HubError("Managed server registration must use its assigned address", 403)
            if payload.get("code_version") != definition["code_version"]:
                raise HubError(
                    "Managed server code version does not match the running snapshot", 409
                )

    async def register(request: Request) -> Response:
        payload = Registration.model_validate(await body(request))
        await authenticate(request, payload.model_dump())
        reused = await hub.upstreams.register(payload.name, payload.url, payload.code_version)
        return JSONResponse(
            {"name": payload.name, "status": "already_registered" if reused else "registered"},
            409 if reused else 201,
        )

    async def unregister(request: Request) -> Response:
        payload = await body(request)
        if set(payload) != {"name"} or not isinstance(payload["name"], str):
            raise HubError("Unregistration requires a server name")
        await authenticate(request, payload)
        await hub.upstreams.unregister(payload["name"])
        return Response(status_code=204)

    return [
        Route("/register", register, methods=["POST"]),
        Route("/unregister", unregister, methods=["POST"]),
    ]


def create_registration_app(hub: Hub) -> Starlette:
    app = Starlette(
        routes=_registration_routes(hub),
        middleware=[Middleware(Boundary, hub=hub, authenticate=False)],
    )
    app.state.hub = hub
    return app


def create_app(
    settings: Settings | None = None,
    *,
    redis: Redis | None = None,
    http_client: httpx.AsyncClient | None = None,
    registry: Registry | None = None,
    background: bool = True,
) -> Starlette:
    settings = settings or Settings.from_env()
    settings.validate()
    hub = Hub(settings, redis, http_client, registry)
    server = Server("mcp-hub")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool.model_validate(tool) for tool in await hub.gateway.listing(request_context.get())
        ]

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        return CallToolResult.model_validate(
            await hub.gateway.call(name, arguments or {}, request_context.get())
        )

    manager = StreamableHTTPSessionManager(
        app=server,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=[
                urlsplit(settings.hub_public_url).netloc,
                *(
                    ["127.0.0.1:*", "localhost:*", "[::1]:*"]
                    if settings.environment == "development"
                    else []
                ),
            ],
            allowed_origins=[settings.hub_public_url],
        ),
        max_request_body_size=settings.max_request_bytes,
    )

    class MCP:
        async def __call__(self, scope, receive, send) -> None:
            await manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(app):
        async with manager.run():
            try:
                await hub.start(background)
                yield
            finally:
                await hub.close()

    async def health(request: Request) -> Response:
        catalog = await hub.store.catalog()
        return JSONResponse(
            {
                "status": "draining" if hub.gateway.draining else "ok",
                "catalog_version": catalog["version"],
                "upstreams": {
                    name: {
                        key: entry.get(key) for key in ("status", "circuit_open", "code_version")
                    }
                    for name, entry in catalog["servers"].items()
                },
            }
        )

    async def ready(request: Request) -> Response:
        try:
            healthy = hub.ready and not hub.gateway.draining and await hub.store_ready()
        except Exception:
            healthy = False
        return JSONResponse({"ready": healthy}, 200 if healthy else 503)

    async def metrics(request: Request) -> Response:
        return Response(hub.metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8")

    async def root(request: Request) -> Response:
        return RedirectResponse("/admin/", 302)

    async def static(request: Request) -> Response:
        relative = request.path_params.get("path", "") or "index.html"
        candidate = (settings.frontend_path / relative).resolve()
        if not candidate.is_relative_to(settings.frontend_path) or not candidate.is_file():
            return JSONResponse(
                {
                    "error": "Console assets are not built. Run npm ci && npm run build in frontend/ or use the container image."
                },
                404,
            )
        return FileResponse(candidate)

    async def hub_error(request: Request, exc: Exception) -> Response:
        assert isinstance(exc, HubError)
        if isinstance(exc, OAuthError):
            endpoint = request.url.path.strip("/").split("/")[0]
            hub.metrics.auth.labels(endpoint, exc.code).inc()
        response = error_response(exc)
        if exc.status == 401 and request.headers.get("authorization", "").startswith("Basic "):
            response.headers["WWW-Authenticate"] = 'Basic realm="mcp-hub"'
        return response

    routes = [
        Route("/", root),
        Route("/health", health),
        Route("/ready", ready),
        Route("/metrics", metrics),
        Route("/mcp", MCP(), methods=["POST", "GET", "DELETE"]),
        Route("/mcp/{alias}", MCP(), methods=["POST", "GET", "DELETE"]),
        *oauth_routes(),
        *management_routes(),
        Route("/admin", root),
        Route("/admin/{path:path}", static),
    ]
    # External, manually managed servers may register on the control listener too.
    # Managed servers only know their per-server scoped key and the separate listener.
    routes.extend(_registration_routes(hub))
    app = Starlette(
        routes=routes,
        lifespan=lifespan,
        middleware=[Middleware(Boundary, hub=hub)],
        exception_handlers={HubError: hub_error},
    )
    app.state.hub, app.state.mcp = hub, manager
    return app
