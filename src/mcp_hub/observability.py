"""Bounded-cardinality metrics and a durable, bounded audit outbox."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from datetime import UTC, datetime
from typing import Any

import httpx
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from .config import Settings
from .security import scrub
from .store import Store, dumps

log = logging.getLogger(__name__)


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "hub_http_requests_total",
            "HTTP transport outcomes",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "hub_http_request_seconds",
            "HTTP transport latency",
            ("method", "route"),
            registry=self.registry,
        )
        self.http_inflight = Gauge(
            "hub_http_inflight", "HTTP requests in flight", ("route",), registry=self.registry
        )

        def counter(name: str, help: str, labels: tuple[str, ...]) -> Counter:
            return Counter("hub_" + name, help, labels, registry=self.registry)

        def gauge(name: str, help: str, labels: tuple[str, ...] = ()) -> Gauge:
            return Gauge("hub_" + name, help, labels, registry=self.registry)

        self.requests = counter(
            "requests_total", "Tool request outcomes", ("server", "category", "status")
        )
        self.denials = counter(
            "acl_denials_total", "ACL decisions", ("server", "category", "reason")
        )
        self.auth = counter(
            "auth_failures_total", "Authentication failures", ("endpoint", "reason")
        )
        self.credentials = counter(
            "credential_source_total", "Credential decisions", ("server", "source")
        )
        self.blocked = counter("guardrail_blocks_total", "Content guardrail decisions", ("server",))
        self.limited = counter("rate_limited_total", "Call rate limits", ("server",))
        self.redactions = counter(
            "redacted_responses_total", "Responses changed by redaction", ("server",)
        )
        self.dropped = counter(
            "audit_dropped_total", "Audit events lost with an explicit warning", ("reason",)
        )
        self.disconnects = counter("upstream_disconnects_total", "Session rebuilds", ("server",))
        self.inflight = gauge("inflight", "Tool requests in flight", ("server",))
        self.upstream = gauge("upstream_connected", "Upstream health", ("server",))
        self.breaker = gauge("circuit_open", "Circuit breaker state", ("server",))
        self.coverage = gauge(
            "annotation_coverage", "Fraction of declared tool annotations", ("server",)
        )
        self.catalog_size = gauge("catalog_tools", "Tools in shared catalog")
        self.catalog_version = gauge("catalog_version", "Shared catalog version")
        self.registered = gauge("registered_upstreams", "Live registry entries")
        self.spool_size = gauge("audit_spool_entries", "Durable audit outbox size")
        self.memory = gauge("store_memory_bytes", "Redis memory usage")
        self.prefix_memory = gauge(
            "store_prefix_bytes", "Sampled Redis memory by state namespace", ("prefix",)
        )
        self.duration = Histogram(
            "hub_request_seconds", "Tool latency", ("server",), registry=self.registry
        )
        self.payload = Histogram(
            "hub_payload_bytes",
            "Serialized payload size",
            ("direction",),
            buckets=(256, 1024, 4096, 16384, 65536, 262144, 1048576, 8388608),
            registry=self.registry,
        )

    def render(self) -> bytes:
        return generate_latest(self.registry)


class Audit:
    def __init__(
        self, store: Store, settings: Settings, metrics: Metrics, client: httpx.AsyncClient
    ):
        self.store, self.settings, self.metrics, self.client = store, settings, metrics, client
        self.wake = asyncio.Event()

    async def append(self, event: dict[str, Any], *, redacted: bool = False) -> None:
        value = {
            "@timestamp": datetime.now(UTC).isoformat(),
            **(event if redacted else scrub(event, audit=True)),
        }
        try:
            size = await self.store.script(
                """
                if redis.call('LLEN',KEYS[1])>=tonumber(ARGV[2]) then redis.call('INCR',KEYS[2]); return -1 end
                return redis.call('RPUSH',KEYS[1],ARGV[1])
            """,
                ["audit:spool", "audit:dropped"],
                [dumps(value), self.settings.audit_spool_max_entries],
            )
            if size == -1:
                self.drop("spool_full")
            else:
                self.metrics.spool_size.set(size)
                self.wake.set()
        except Exception:
            self.drop("store_unavailable")

    def drop(self, reason: str) -> None:
        self.metrics.dropped.labels(reason).inc()
        log.warning("Audit event dropped: %s", reason)

    async def flush(self) -> int:
        if not self.settings.audit_sink_url:
            return 0
        owner = secrets.token_urlsafe(16)
        if not await self.store.put("audit:flush-lock", owner, ttl=15, nx=True):
            return 0
        sent = 0
        try:
            for _ in range(100):
                raw = await self.store.redis.lindex(self.store.key("audit:spool"), 0)
                if raw is None:
                    break
                import json

                event = json.loads(raw)
                age = (
                    datetime.now(UTC) - datetime.fromisoformat(event["@timestamp"])
                ).total_seconds()
                if age > self.settings.audit_retention_days * 86400:
                    self.drop("retention_expired")
                else:
                    day = event["@timestamp"][:10]
                    url = f"{self.settings.audit_sink_url.rstrip('/')}/hub-audit-{day}/_doc/{event['request_id']}"
                    response = await self.client.put(
                        url,
                        json=event,
                        auth=httpx.BasicAuth(
                            self.settings.audit_sink_user, self.settings.audit_sink_password
                        )
                        if self.settings.audit_sink_user
                        else httpx.Auth(),
                        timeout=5,
                    )
                    response.raise_for_status()
                removed = await self.store.script(
                    """
                    if redis.call('GET',KEYS[2])~=ARGV[2] then return 0 end
                    if redis.call('LINDEX',KEYS[1],0)==ARGV[1] then redis.call('LPOP',KEYS[1]); return 1 end
                    return 0
                """,
                    ["audit:spool", "audit:flush-lock"],
                    [raw, dumps(owner)],
                )
                if not removed:
                    break
                sent += 1
                await self.store.redis.expire(self.store.key("audit:flush-lock"), 15)
            self.metrics.spool_size.set(await self.store.redis.llen(self.store.key("audit:spool")))
        finally:
            await self.store.unlock("audit:flush-lock", owner)
        return sent

    async def run(self) -> None:
        if not self.settings.audit_sink_url:
            log.warning("AUDIT_SINK_URL is unset; audit remains in the bounded durable outbox")
        while True:
            try:
                await self.flush()
            except Exception as exc:
                log.warning("Audit sink unavailable: %s", type(exc).__name__)
            self.wake.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.wake.wait(), timeout=5)
