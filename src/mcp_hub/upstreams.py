"""Persistent SDK sessions owned by dedicated tasks, plus a shared catalog."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack, suppress
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError

from .config import Settings
from .models import HubError
from .observability import Metrics
from .security import category, public_schema
from .store import Store, dumps
from .tls import trust

log = logging.getLogger(__name__)


class ResponseLimitError(Exception):
    pass


class LimitedStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpx.AsyncByteStream, limit: int):
        self.stream, self.limit = stream, limit

    async def __aiter__(self):
        size = 0
        async for chunk in self.stream:
            size += len(chunk)
            if size > self.limit:
                raise ResponseLimitError("Upstream response exceeded the transport byte limit")
            yield chunk

    async def aclose(self) -> None:
        await self.stream.aclose()


class LimitedTransport(httpx.AsyncBaseTransport):
    def __init__(self, limit: int, *, ca_bundle: str = ""):
        self.inner, self.limit = httpx.AsyncHTTPTransport(verify=trust(ca_bundle)), limit

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.headers["accept-encoding"] = "identity"
        response = await self.inner.handle_async_request(request)
        # Reject compression so decompression cannot expand a bounded wire payload into a bomb.
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            await response.aclose()
            raise ResponseLimitError("Compressed upstream responses are not accepted")
        length = response.headers.get("content-length")
        if length and int(length) > self.limit:
            await response.aclose()
            raise ResponseLimitError("Upstream Content-Length exceeds the transport byte limit")
        assert isinstance(response.stream, httpx.AsyncByteStream)
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=LimitedStream(response.stream, self.limit),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self.inner.aclose()


@dataclass(slots=True)
class Circuit:
    threshold: int
    backoff: float
    failures: int = 0
    open_until: float = 0
    attempts: int = 0
    probing: bool = False

    @property
    def opened(self) -> bool:
        return self.open_until > 0

    def allow(self) -> bool:
        if not self.opened:
            return True
        if time.monotonic() >= self.open_until and not self.probing:
            self.probing = True
            return True
        return False

    def success(self) -> None:
        self.failures = self.attempts = 0
        self.open_until = 0
        self.probing = False

    def failure(self) -> bool:
        self.failures += 1
        self.probing = False
        if self.threshold and self.failures >= self.threshold:
            self.attempts += 1
            self.open_until = time.monotonic() + min(
                300, self.backoff * 2 ** min(self.attempts - 1, 10)
            )
            return True
        return False


class Session:
    def __init__(self, url: str, secret: str, settings: Settings):
        self.url, self.secret, self.settings = url, secret, settings
        self.client: ClientSession | None = None
        self.stop = asyncio.Event()
        self.ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self.task: asyncio.Task[None] | None = None

    @property
    def alive(self) -> bool:
        return self.client is not None and self.task is not None and not self.task.done()

    def _http(self, headers=None, timeout=None, auth=None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout or 30,
            auth=auth,
            transport=LimitedTransport(
                self.settings.max_upstream_response_bytes, ca_bundle=self.settings.hub_ca_bundle
            ),
            follow_redirects=False,
            trust_env=False,
        )

    async def _serve(self) -> None:
        try:
            async with AsyncExitStack() as stack:
                http = await stack.enter_async_context(
                    self._http(
                        headers={"x-hub-upstream-secret": self.secret},
                        timeout=httpx.Timeout(
                            self.settings.upstream_list_tools_timeout,
                            read=self.settings.upstream_call_tool_timeout,
                        ),
                    )
                )
                read, write, _ = await stack.enter_async_context(
                    streamable_http_client(self.url, http_client=http)
                )
                client = await stack.enter_async_context(
                    ClientSession(
                        read,
                        write,
                        read_timeout_seconds=timedelta(seconds=self.settings.session_read_timeout),
                    )
                )
                await client.initialize()
                self.client = client
                self.ready.set_result(None)
                await self.stop.wait()
        except BaseException as exc:
            if not self.ready.done():
                self.ready.set_exception(exc)
            elif not isinstance(exc, asyncio.CancelledError):
                log.warning("Upstream session ended: %s", type(exc).__name__)
        finally:
            self.client = None

    async def connect(self) -> None:
        self.task = asyncio.create_task(self._serve())
        try:
            await asyncio.wait_for(
                asyncio.shield(self.ready), timeout=self.settings.upstream_list_tools_timeout
            )
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        self.stop.set()
        if self.task:
            try:
                await asyncio.wait_for(asyncio.shield(self.task), timeout=3)
            except TimeoutError:
                self.task.cancel()
                await asyncio.gather(self.task, return_exceptions=True)

    async def tools(self) -> list[dict[str, Any]]:
        if not self.client:
            raise HubError("Upstream is disconnected; use hub.discover_tools", 502)
        result: list[dict[str, Any]] = []
        received = 0
        cursor = None
        async with asyncio.timeout(self.settings.upstream_list_tools_timeout):
            for _ in range(100):
                page = await self.client.list_tools(cursor=cursor)
                if len(result) + len(page.tools) > self.settings.max_upstream_tools:
                    raise HubError("Upstream exceeded the tool count limit", 502)
                serialized = [
                    tool.model_dump(by_alias=True, exclude_none=True) for tool in page.tools
                ]
                received += len(dumps(serialized).encode())
                if received > self.settings.max_upstream_response_bytes:
                    raise HubError(
                        "Paginated upstream catalog exceeded the aggregate byte limit", 502
                    )
                result.extend(serialized)
                cursor = page.nextCursor
                if not cursor:
                    return result
        raise HubError("Upstream tool catalog exceeded the pagination limit", 502)

    async def ping(self) -> None:
        if not self.client:
            raise ConnectionError
        async with asyncio.timeout(self.settings.upstream_list_tools_timeout):
            await self.client.send_ping()

    async def call(
        self, name: str, arguments: dict[str, Any], budget: float, request_id: str
    ) -> dict[str, Any]:
        if not self.client:
            raise HubError("Upstream is disconnected; use hub.discover_tools", 502)
        try:
            result = await self.client.call_tool(
                name,
                arguments,
                read_timeout_seconds=timedelta(seconds=budget),
                meta={"hub/request_id": request_id},
            )
        except McpError as exc:
            # Python SDK uses HTTP 408; TypeScript peers may use JSON-RPC -32001.
            if exc.error.code in {408, -32001}:
                raise TimeoutError("Upstream request budget elapsed") from exc
            raise
        return result.model_dump(by_alias=True, exclude_none=True)


class Upstreams:
    def __init__(self, store: Store, settings: Settings, metrics: Metrics):
        self.store, self.settings, self.metrics = store, settings, metrics
        self.sessions: dict[str, Session] = {}
        self.circuits: dict[str, Circuit] = {}
        self.wake = asyncio.Event()
        self._lock = asyncio.Lock()
        self.ensure_network: Callable[[str], Awaitable[None]] | None = None

    def circuit(self, name: str) -> Circuit:
        return self.circuits.setdefault(
            name,
            Circuit(
                self.settings.circuit_breaker_threshold, self.settings.circuit_breaker_base_backoff
            ),
        )

    def secret(self, name: str, dynamic: bool) -> str:
        if dynamic:
            import hashlib
            import hmac

            return hmac.new(
                self.settings.hub_upstream_secret.encode(),
                ("upstream:" + name).encode(),
                hashlib.sha256,
            ).hexdigest()
        return self.settings.hub_upstream_secret

    def validate_url(self, url: str) -> None:
        try:
            parsed = urlsplit(url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.fragment
            ):
                raise ValueError
            _ = parsed.port
        except ValueError as exc:
            raise HubError(
                "Upstream URL must be HTTP(S), without credentials or a fragment"
            ) from exc
        allowed = {
            host.strip()
            for host in self.settings.hub_allowed_register_hosts.split(",")
            if host.strip()
        }
        if allowed and parsed.hostname not in allowed:
            raise HubError("Upstream hostname is not in HUB_ALLOWED_REGISTER_HOSTS", 403)

    async def register(self, name: str, url: str, code_version: str = "") -> bool:
        if name == "hub":
            raise HubError("The hub namespace is reserved", 409)
        self.validate_url(url)
        async with self._lock:
            existing = (await self.store.registered()).get(name)
            if existing and existing["url"] != url:
                raise HubError(
                    "Name is already registered at another address; unregister it first", 409
                )
            definition = (await self.store.dynamic()).get(name)
            session = self.sessions.get(name)
            reused = False
            if session and session.alive and session.url == url:
                try:
                    await session.ping()
                    reused = True
                except Exception:
                    await session.close()
                    self.sessions.pop(name, None)
            if not reused:
                session = Session(url, self.secret(name, definition is not None), self.settings)
                try:
                    await session.connect()
                except Exception as exc:
                    raise HubError(
                        "Upstream MCP handshake failed; inspect the server logs", 502
                    ) from exc
                self.sessions[name] = session
            value = {
                "name": name,
                "url": url,
                "code_version": code_version,
                "heartbeat": time.time(),
            }
            if not await self.store.register(name, value, self.settings.heartbeat_interval * 3):
                raise HubError("Name is already registered at another address", 409)
            self.circuit(name).success()
            self.wake.set()
            return reused

    async def unregister(self, name: str) -> None:
        async with self._lock:
            await self.store.unregister(name)
            session = self.sessions.pop(name, None)
            if session:
                await session.close()
            self.circuits.pop(name, None)
            self.wake.set()

    async def refresh(self) -> bool:
        # Each replica maintains its own sessions. Catalog writes are serialized in Redis.
        async with self._lock:
            generation, registered = await self.store.registered_snapshot()
            definitions = await self.store.dynamic()
            old = (await self.store.catalog())["servers"]
            for name in list(self.sessions):
                if name not in registered:
                    await self.sessions.pop(name).close()
                    self.circuits.pop(name, None)

            async def refresh_one(name: str, data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
                circuit = self.circuit(name)
                previous = old.get(name, {"tools": []})
                definition = definitions.get(name, {})
                base = {
                    "code_version": data.get("code_version", ""),
                    "policy": definition.get("policy", "both"),
                    "status": "degraded",
                    "tools": previous["tools"],
                    "circuit_open": circuit.opened,
                }
                if not circuit.allow():
                    return name, base
                try:
                    session = self.sessions.get(name)
                    if not session or not session.alive or session.url != data["url"]:
                        if name in definitions and self.ensure_network:
                            await self.ensure_network(name)
                        if session:
                            await session.close()
                        session = Session(
                            data["url"], self.secret(name, name in definitions), self.settings
                        )
                        await session.connect()
                        self.sessions[name] = session
                    tools = await session.tools()
                    normalized = []
                    for tool in tools:
                        if not re_tool_name(tool.get("name", "")):
                            continue
                        if "credentials" not in tool.get("inputSchema", {}).get("properties", {}):
                            raise HubError(
                                "Every upstream tool must explicitly declare its credentials argument; caller identity cannot otherwise be guaranteed",
                                502,
                            )
                        kind, annotated = category(tool)
                        schema = public_schema(
                            tool.get("inputSchema", {"type": "object", "properties": {}})
                        )
                        normalized.append(
                            {
                                "name": tool["name"],
                                "description": tool.get("description", ""),
                                "inputSchema": schema,
                                "category": kind,
                                "annotated": annotated,
                                "accepts_credentials": "credentials"
                                in tool.get("inputSchema", {}).get("properties", {}),
                                "annotations": tool.get("annotations"),
                            }
                        )
                    circuit.success()
                    self.metrics.breaker.labels(name).set(0)
                    self.metrics.upstream.labels(name).set(1)
                    self.metrics.coverage.labels(name).set(
                        sum(t["annotated"] for t in normalized) / len(normalized)
                        if normalized
                        else 1
                    )
                    return name, {
                        **base,
                        "tools": normalized,
                        "status": "connected",
                        "circuit_open": False,
                    }
                except Exception as exc:
                    log.warning(
                        "Catalog refresh failed for %s: %s",
                        name,
                        exc.message if isinstance(exc, HubError) else type(exc).__name__,
                    )
                    opened = circuit.failure()
                    self.metrics.upstream.labels(name).set(0)
                    self.metrics.breaker.labels(name).set(opened)
                    if opened and name in self.sessions:
                        await self.sessions.pop(name).close()
                        self.metrics.disconnects.labels(name).inc()
                    return name, {**base, "circuit_open": opened}

            servers = dict(
                await asyncio.gather(
                    *(refresh_one(name, data) for name, data in registered.items())
                )
            )
            version = await self.store.publish_catalog(servers, generation=generation)
            if version < 0:
                self.wake.set()
                return False
            self.metrics.registered.set(len(registered))
            self.metrics.catalog_size.set(sum(len(value["tools"]) for value in servers.values()))
            self.metrics.catalog_version.set(version)
            return True

    async def run(self) -> None:
        while True:
            self.wake.clear()
            try:
                await self.refresh()
            except Exception as exc:
                log.warning("Catalog reconciliation failed: %s", type(exc).__name__)
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self.wake.wait(),
                    timeout=min(
                        self.settings.catalog_refresh_interval,
                        self.settings.registry_reconcile_interval,
                    ),
                )

    async def close(self) -> None:
        await asyncio.gather(*(session.close() for session in self.sessions.values()))
        self.sessions.clear()


def re_tool_name(name: str) -> bool:
    import re

    return bool(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name, flags=re.ASCII))
