"""The ordered tool pipeline: identity, ACL, policy, upstream, redaction, audit."""

from __future__ import annotations

import asyncio
import contextvars
import hmac
import json
import logging
import math
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import anyio
from mcp.shared.exceptions import McpError
from opentelemetry import trace

from .acl import ACL, Access
from .arguments import validate_arguments, validate_json
from .config import Settings
from .credentials import Credentials
from .models import RESERVED_ARGS, HubError, Principal
from .observability import Audit, Metrics
from .security import active_secrets, cap_text, category, scrub, scrub_text, secret_values
from .store import Store, digest, dumps
from .upstreams import Upstreams

log = logging.getLogger(__name__)
tracer = trace.get_tracer("mcp_hub")


@dataclass(slots=True)
class RequestContext:
    principal: Principal
    ip: str = ""
    credentials_header: str | None = field(default=None, repr=False)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    catalog_version: int = 0
    access: Access | None = None
    retry_after: int = 0
    upstream_seconds: float = 0.0


request_context: contextvars.ContextVar[RequestContext] = contextvars.ContextVar("hub_request")


class Completed(Exception):
    def __init__(self, result: dict[str, Any], status: str):
        self.result, self.status = result, status


class Gateway:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        acl: ACL,
        credentials: Credentials,
        upstreams: Upstreams,
        audit: Audit,
        metrics: Metrics,
    ):
        self.store, self.settings, self.acl = store, settings, acl
        self.credentials, self.upstreams, self.audit, self.metrics = (
            credentials,
            upstreams,
            audit,
            metrics,
        )
        self.draining = False
        self.tasks: set[asyncio.Task[Any]] = set()
        self.rules = json.loads(settings.guardrail_rules)
        if not isinstance(self.rules, list):
            raise ValueError("GUARDRAIL_RULES must be a JSON array of literal-match rules")

    async def access(self, context: RequestContext) -> Access:
        if context.access is None:
            context.access = await self.acl.snapshot(context.principal)
        return context.access

    async def listing(self, context: RequestContext) -> list[dict[str, Any]]:
        access, catalog = await asyncio.gather(self.access(context), self.store.catalog())
        context.catalog_version = catalog["version"]
        tools = []
        for server, entry in catalog["servers"].items():
            for tool in entry["tools"]:
                if access.permits(server, category(tool)[0]):
                    public = {key: tool[key] for key in ("description", "inputSchema")}
                    if tool.get("annotations"):
                        public["annotations"] = tool["annotations"]
                    tools.append({**public, "name": f"{server}.{tool['name']}"})
        tools.append(
            {
                "name": "hub.discover_tools",
                "description": "Discover the current servers and tools you may use, including their status and catalog/code versions. Use this when a tool was added, removed, renamed or is unavailable.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "annotations": {"readOnlyHint": True, "destructiveHint": False},
            }
        )
        return tools

    async def discover(self, context: RequestContext) -> dict[str, Any]:
        access, catalog = await asyncio.gather(self.access(context), self.store.catalog())
        context.catalog_version = catalog["version"]
        return {
            "catalog_version": catalog["version"],
            "servers": [
                {
                    "name": server,
                    "status": entry["status"],
                    "code_version": entry.get("code_version", ""),
                    "credentials_policy": entry.get("policy", "both"),
                    "tools": [
                        {"name": f"{server}.{tool['name']}", "category": category(tool)[0]}
                        for tool in entry["tools"]
                        if access.permits(server, category(tool)[0])
                    ],
                }
                for server, entry in catalog["servers"].items()
                if access.capabilities(server)
            ],
        }

    def _guard(self, name: str, arguments: dict[str, Any]) -> None:
        for rule in self.rules:
            if "*" not in rule.get("tools", []) and name not in rule.get("tools", []):
                continue
            inspected = (
                arguments
                if not rule.get("keys")
                else {key: arguments[key] for key in rule["keys"] if key in arguments}
            )
            text = dumps(inspected).casefold()
            if any(str(pattern).casefold() in text for pattern in rule.get("contains", [])):
                raise HubError(
                    "Arguments match a blocked destructive endpoint. Changing the prompt does not override this policy.",
                    403,
                    code="blocked_content",
                )

    async def _approval(
        self,
        context: RequestContext,
        name: str,
        arguments: dict[str, Any],
        fingerprint: str,
        definition: dict[str, Any],
        access: Access,
        execution_context: str,
        execution_summary: dict[str, str],
    ) -> str | None:
        if not definition.get("approval_required") and not access.group.get("approval_required"):
            return None
        if len(dumps(arguments).encode()) > self.settings.max_approval_argument_bytes:
            raise HubError(
                "Arguments exceed the human-review size limit; narrow the action",
                413,
                code="approval_too_large",
            )
        lookup = "approval:lookup:" + fingerprint
        approval_id = await self.store.get(lookup)
        approval = await self.store.get("approval:" + approval_id) if approval_id else None
        if approval and not self._same_execution(approval, execution_context):
            # Detach only the observed pointer. A concurrent request may already have replaced it.
            changed = await self.store.script(
                """
                if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end
                local raw=redis.call('GET',KEYS[2])
                local ttl=redis.call('TTL',KEYS[2])
                if raw and ttl>0 then
                    local a=cjson.decode(raw)
                    if a.status=='pending' or a.status=='approved' then
                        a.status='superseded'
                        redis.call('SET',KEYS[2],cjson.encode(a),'EX',ttl)
                    end
                end
                redis.call('DEL',KEYS[1]); return 1
                """,
                [lookup, "approval:" + approval_id],
                [dumps(approval_id)],
            )
            if not changed:
                raise HubError(
                    "Approval context changed concurrently; retry the call",
                    409,
                    code="blocked_approval",
                )
            approval = None
        if approval and approval.get("status") == "approved":
            if (
                definition.get("approval_four_eyes")
                and approval.get("decided_by") == context.principal.id
            ):
                await self.store.delete(lookup)
                approval = None
            else:
                return approval_id
        if approval and approval.get("status") == "consumed":
            if definition.get("idempotency", True) and await self.store.get("idem:" + fingerprint):
                return approval_id
            await self.store.delete(lookup)
            approval = None
        if approval and approval.get("status") == "rejected":
            raise HubError(
                "This destructive action was rejected in the console", 403, code="blocked_approval"
            )
        if not approval:
            approval_id = secrets.token_urlsafe(24)
            approval = {
                "id": approval_id,
                "principal": context.principal.model_dump(),
                "tool": name,
                "arguments": self.credentials.cipher.encrypt(arguments),
                "arguments_summary": scrub(arguments, audit=True),
                "status": "pending",
                "four_eyes": bool(definition.get("approval_four_eyes")),
                "created_at": datetime.now(UTC).isoformat(),
                "execution_context": self.credentials.cipher.encrypt(execution_context),
                "execution_summary": execution_summary,
            }
            created = await self.store.script(
                """
                local id=redis.call('GET',KEYS[1]); if id then return id end
                redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[3]); redis.call('SET',KEYS[2],ARGV[2],'EX',ARGV[3]);
                redis.call('ZREMRANGEBYSCORE',KEYS[3],'-inf',tonumber(ARGV[4])-tonumber(ARGV[3]));
                redis.call('ZADD',KEYS[3],ARGV[4],ARGV[5]); return ARGV[1]
            """,
                [lookup, "approval:" + approval_id, "approval:_index"],
                [
                    dumps(approval_id),
                    dumps(approval),
                    self.settings.approval_ttl,
                    int(time.time()),
                    approval_id,
                ],
            )
            approval_id = json.loads(created)
        raise HubError(
            f"Human approval required. Open the console's Approvals view and review request {approval_id}; then retry the same call. An argument or prompt cannot approve it.",
            403,
            code="blocked_approval",
        )

    def _same_execution(self, record: dict[str, Any], execution_context: str) -> bool:
        encrypted = record.get("execution_context")
        if not isinstance(encrypted, str):
            return False
        saved = self.credentials.cipher.decrypt(encrypted)
        return isinstance(saved, str) and hmac.compare_digest(saved, execution_context)

    def _replay(self, record: dict[str, Any] | None, execution_context: str) -> None:
        if record and not self._same_execution(record, execution_context):
            raise HubError(
                "An earlier write used a different connection or tool revision. Inspect its outcome before making a new request; it will not be replayed or executed again in this window.",
                409,
                code="idempotency_context_changed",
            )
        if record and record.get("state") == "done":
            raise Completed(record["result"], "idempotent_replay")
        raise HubError(
            "An identical write is in progress or has an uncertain outcome. Wait and check its result; it will not be executed twice.",
            409,
            code="idempotency_pending",
            retry_after=1,
        )

    async def _consume_approval(self, identifier: str, fingerprint: str, idempotent: bool) -> None:
        key = "approval:" + identifier
        raw = await self.store.redis.get(self.store.key(key))
        value = json.loads(raw) if raw else None
        if not value or value["status"] != "approved":
            raise HubError(
                "Approval expired or was consumed by another request", 409, code="blocked_approval"
            )
        value["status"] = "consumed"
        accepted = await self.store.script(
            """
            if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end
            local ttl=redis.call('TTL',KEYS[1]); if ttl<=0 then return 0 end
            redis.call('SET',KEYS[1],ARGV[2],'EX',ttl)
            if ARGV[3]=='0' then redis.call('DEL',KEYS[2]) end
            return 1
        """,
            [key, "approval:lookup:" + fingerprint],
            [raw, dumps(value), "1" if idempotent else "0"],
        )
        if not accepted:
            raise HubError(
                "Approval was consumed concurrently; request was not executed",
                409,
                code="blocked_approval",
            )

    async def call(
        self, name: str, arguments: dict[str, Any], context: RequestContext
    ) -> dict[str, Any]:
        started = time.monotonic()
        # Only protocol-sized names enter telemetry, logs, provenance or audit records.
        valid_name = bool(re.fullmatch(r"[a-z0-9_-]{1,64}\.[A-Za-z0-9_-]{1,128}", name))
        name = name if valid_name else "invalid_tool"
        request_id = str(uuid.uuid4())
        context.request_id = request_id
        server, separator, tool_name = name.partition(".")
        server_label, kind, source, status = "_unknown", "read", "none", "error"
        result: dict[str, Any] = {}
        clean = {key: value for key, value in arguments.items() if key not in RESERVED_ARGS}
        idem_key: str | None = None
        idem_owner = False
        invoked = False
        approval_id = None
        encrypted_context = None
        secret_token = None
        task = asyncio.current_task()
        if task:
            self.tasks.add(task)
        with tracer.start_as_current_span(
            "mcp.tool_call", attributes={"hub.request_id": request_id, "mcp.tool": name}
        ):
            try:
                if self.draining:
                    raise HubError(
                        "Hub is shutting down; retry against a ready instance",
                        503,
                        code="service_shutdown",
                    )
                try:
                    validate_json(arguments)
                except HubError:
                    clean = {
                        "_omitted": "Arguments exceeded JSON nesting, element or encoding limits"
                    }
                    raise
                if not valid_name or not separator or not server or not tool_name:
                    raise HubError(
                        "Use {server}.{tool}; call hub.discover_tools to find valid names",
                        code="invalid_tool",
                    )
                catalog, access = await asyncio.gather(self.store.catalog(), self.access(context))
                context.catalog_version = catalog["version"]
                if server == "hub" and tool_name == "discover_tools":
                    server_label = "hub"
                elif server in catalog["servers"]:
                    server_label = server
                known = catalog["servers"].get(server)
                rate_name = (
                    name
                    if name == "hub.discover_tools"
                    or (known and any(tool["name"] == tool_name for tool in known["tools"]))
                    else "_unknown"
                )
                limit_key = digest(context.principal.id + "\0" + rate_name)
                allowed, retry = await self.store.rate(
                    "tool:" + limit_key,
                    self.settings.hub_tool_rate_limit,
                    self.settings.hub_tool_rate_window,
                )
                if not allowed:
                    self.metrics.limited.labels(server_label).inc()
                    raise HubError(
                        "Tool rate limit reached. Repeating an identical call will not produce new information; wait before retrying.",
                        429,
                        code="rate_limited",
                        retry_after=retry,
                    )
                allowed, retry = await self.store.rate(
                    "daily:"
                    + digest(context.principal.id)
                    + ":"
                    + datetime.now(UTC).strftime("%Y-%m-%d"),
                    self.settings.hub_daily_call_budget,
                    86400,
                )
                if not allowed:
                    raise HubError(
                        "Daily call budget exhausted; wait for the next UTC day",
                        429,
                        code="rate_limited",
                        retry_after=retry,
                    )
                if name == "hub.discover_tools":
                    result = {
                        "content": [{"type": "text", "text": dumps(await self.discover(context))}],
                        "isError": False,
                    }
                    raise Completed(result, "ok")
                entry = catalog["servers"].get(server)
                if not entry:
                    available = sorted(s for s in catalog["servers"] if access.capabilities(s))
                    raise HubError(
                        f"Unknown server. Available servers: {', '.join(available) or '(none)'}. Use hub.discover_tools.",
                        404,
                        code="unknown_server",
                    )
                tool = next((tool for tool in entry["tools"] if tool["name"] == tool_name), None)
                if not tool:
                    raise HubError(
                        "Tool may have been removed or renamed. Call hub.discover_tools for current names.",
                        404,
                        code="unknown_tool",
                    )
                # Re-evaluate persisted catalogs as well as freshly discovered tools.
                kind = category(tool)[0]
                if not access.permits(server, kind):
                    reason = "capability" if access.capabilities(server) else "server"
                    self.metrics.denials.labels(server, kind, reason).inc()
                    raise HubError(
                        "Access denied by the server/capability policy", 403, code="blocked_acl"
                    )
                definition = access.definitions.get(server, {})
                if definition.get("status") == "stopping":
                    raise HubError(
                        "Server is stopping; no new calls are accepted", 503, code="server_stopping"
                    )
                fingerprint = digest(context.principal.id + "\0" + name + "\0" + dumps(clean))
                validate_arguments(tool["inputSchema"], clean)
                resolved = await self.credentials.resolve(
                    context.principal,
                    server,
                    definition.get("policy", entry.get("policy", "both")),
                    context.credentials_header,
                    required_fields=definition.get("user_env_fields", []),
                )
                source = resolved.source
                self.metrics.credentials.labels(server, source).inc()
                global_values = await self.credentials.global_env(server, running=True)
                session = self.upstreams.sessions.get(server)
                execution_context = "execution-v1:" + digest(
                    dumps(
                        {
                            "client_id": context.principal.client_id,
                            "kind": context.principal.kind,
                            "credentials": resolved.credentials,
                            "credentials_source": source,
                            "global_env": global_values,
                            "policy": definition.get("policy", entry.get("policy", "both")),
                            "code_version": entry.get("code_version", ""),
                            "endpoint": getattr(session, "url", entry.get("url", "")),
                            "schema": digest(dumps(tool["inputSchema"])),
                            "category": kind,
                        }
                    )
                )
                encrypted_context = self.credentials.cipher.encrypt(execution_context)
                known_secrets = (
                    secret_values(resolved.credentials)
                    + secret_values(global_values)
                    + (
                        self.settings.hub_registration_secret,
                        self.settings.hub_upstream_secret,
                        self.upstreams.secret(server, server in access.definitions),
                    )
                )
                secret_token = active_secrets.set(known_secrets)
                try:
                    self._guard(name, clean)
                except HubError:
                    self.metrics.blocked.labels(server).inc()
                    raise
                if kind != "read" and definition.get("idempotency", True):
                    existing = await self.store.get("idem:" + fingerprint)
                    if existing:
                        self._replay(existing, execution_context)
                circuit = self.upstreams.circuit(server)
                if circuit.opened:
                    raise HubError(
                        "Upstream circuit is open; the hub will probe recovery automatically. Use hub.discover_tools.",
                        502,
                        code="circuit_open",
                    )
                if not session or not session.alive:
                    raise HubError(
                        "Upstream is disconnected. Call hub.discover_tools; the hub is reconnecting.",
                        502,
                        code="disconnected",
                    )
                if not entry.get("tools_validated", False):
                    raise HubError(
                        "Tool catalog is not currently validated; wait for rediscovery",
                        503,
                        code="catalog_unavailable",
                    )
                if kind == "destructive":
                    approval_id = await self._approval(
                        context,
                        name,
                        clean,
                        fingerprint,
                        definition,
                        access,
                        execution_context,
                        {
                            "credentials_source": source,
                            "code_version": entry.get("code_version", ""),
                        },
                    )
                if kind != "read" and definition.get("idempotency", True):
                    idem_key = "idem:" + fingerprint
                    claim = {
                        "state": "pending",
                        "request_id": request_id,
                        "execution_context": encrypted_context,
                    }
                    idem_owner = await self.store.put(
                        idem_key,
                        claim,
                        ttl=max(
                            self.settings.idempotency_ttl,
                            math.ceil(self.settings.upstream_call_tool_timeout) + 30,
                        ),
                        nx=True,
                    )
                    if not idem_owner:
                        stored = await self.store.get(idem_key)
                        self._replay(stored, execution_context)
                forwarded = dict(clean)
                if tool.get("accepts_credentials"):
                    forwarded["credentials"] = resolved.credentials
                ceiling = min(
                    definition.get("call_timeout") or self.settings.upstream_call_tool_timeout,
                    self.settings.upstream_call_tool_timeout,
                )
                budget = min(
                    definition.get("read_timeout") or self.settings.session_read_timeout,
                    ceiling * 0.9,
                )
                if approval_id:
                    await self._consume_approval(
                        approval_id, fingerprint, definition.get("idempotency", True)
                    )
                self.metrics.inflight.labels(server).inc()
                upstream_began = time.monotonic()
                try:
                    with tracer.start_as_current_span(
                        "mcp.upstream",
                        attributes={"hub.request_id": request_id, "hub.server": server},
                    ):
                        async with asyncio.timeout(ceiling):
                            invoked = True
                            result = await session.call(tool_name, forwarded, budget, request_id)
                    circuit.success()
                except (TimeoutError, McpError) as exc:
                    if isinstance(exc, TimeoutError) or (
                        isinstance(exc, McpError) and exc.error.code in {408, -32001}
                    ):
                        raise HubError(
                            "This request exceeded its time budget. Narrow the query; the upstream session remains available. A write may have completed, so check its result before retrying.",
                            504,
                            code="timeout",
                        ) from exc
                    raise HubError(
                        "Upstream rejected this tool call; inspect its schema and server logs",
                        502,
                        code="upstream_error",
                    ) from exc
                except Exception as exc:
                    circuit.failure()
                    self.metrics.breaker.labels(server).set(circuit.opened)
                    raise HubError(
                        "Upstream transport failed. Use hub.discover_tools and inspect server health.",
                        502,
                        code="upstream_error",
                    ) from exc
                finally:
                    context.upstream_seconds += time.monotonic() - upstream_began
                    self.metrics.inflight.labels(server).dec()
                status = "upstream_error" if result.get("isError") else "ok"
            except Completed as completed:
                result, status = completed.result, completed.status
            except HubError as exc:
                status = exc.code
                if exc.code.startswith("credentials_") or exc.code == "decryption_failed":
                    source = "blocked"
                    self.metrics.credentials.labels(server_label, source).inc()
                context.retry_after = exc.retry_after
                result = {
                    "isError": True,
                    "content": [{"type": "text", "text": exc.message}],
                    "_meta": {"hub/error": exc.code, "hub/retry_after": exc.retry_after},
                }
            except asyncio.CancelledError:
                status = "service_shutdown" if self.draining else "request_cancelled"
                result = {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": "Request cancelled while the service was shutting down; a write may have an uncertain outcome",
                        }
                    ],
                }
            except Exception as exc:
                status = "internal_error"
                log.error(
                    "Tool request failed: %s", type(exc).__name__, extra={"request_id": request_id}
                )
                result = {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": "Hub could not complete this call. Use the request_id to investigate; a write may have an uncertain outcome.",
                        }
                    ],
                }
            finally:
                with anyio.CancelScope(shield=True):
                    elapsed = time.monotonic() - started
                    original_id = None
                    if status == "idempotent_replay":
                        original_id = (
                            result.get("_meta", {}).get("hub/provenance", {}).get("request_id")
                        )
                        result["content"] = [
                            item
                            for item in result.get("content", [])
                            if not item.get("text", "").startswith("[hub provenance] ")
                        ]
                    original = dumps(result)
                    if self.settings.hub_secret_scrubbing_enabled and status != "idempotent_replay":
                        result = scrub(result)
                    serialized = dumps(result)
                    if serialized != original:
                        self.metrics.redactions.labels(server_label).inc()
                    original_size = len(serialized)
                    if (
                        self.settings.max_response_chars
                        and original_size > self.settings.max_response_chars
                    ):
                        result = {
                            "content": [
                                {
                                    "type": "text",
                                    "text": cap_text(serialized, self.settings.max_response_chars),
                                }
                            ],
                            "isError": bool(result.get("isError")),
                        }
                    provenance = {
                        "source": scrub_text(name),
                        "category": kind,
                        "size_chars": original_size,
                        "duration_ms": round(elapsed * 1000, 3),
                        "request_id": request_id,
                    }
                    result.setdefault("_meta", {})["hub/provenance"] = provenance
                    if original_id:
                        result["_meta"]["hub/original_request_id"] = original_id
                    if self.settings.hub_provenance_footer:
                        result.setdefault("content", []).append(
                            {"type": "text", "text": "[hub provenance] " + dumps(provenance)}
                        )
                    audit_arguments = scrub(clean, audit=True)
                    if idem_key and idem_owner:
                        try:
                            if invoked:
                                await asyncio.shield(
                                    self.store.put(
                                        idem_key,
                                        {
                                            "state": "done",
                                            "result": result,
                                            "execution_context": encrypted_context,
                                        },
                                        ttl=self.settings.idempotency_ttl,
                                    )
                                )
                            else:
                                await asyncio.shield(self.store.delete(idem_key))
                        except Exception:
                            log.warning(
                                "Idempotency result could not be persisted; an uncertain write will not be replayed automatically",
                                extra={"request_id": request_id},
                            )
                    self.metrics.requests.labels(server_label, kind, status).inc()
                    self.metrics.duration.labels(server_label).observe(elapsed)
                    self.metrics.payload.labels("response").observe(len(dumps(result).encode()))
                    await asyncio.shield(
                        self.audit.append(
                            {
                                "request_id": request_id,
                                "tool": scrub_text(name),
                                "server": server_label,
                                "category": kind,
                                "principal_id": context.principal.id,
                                "username": context.principal.username,
                                "client_id": context.principal.client_id,
                                "token_type": context.principal.kind,
                                "client_ip": context.ip,
                                "credentials_source": source,
                                "arguments": audit_arguments,
                                "arguments_summary": cap_text(dumps(audit_arguments), 512),
                                "status": status,
                                "duration_ms": round(elapsed * 1000, 3),
                                "response_size": len(dumps(result)),
                                "response_preview": cap_text(dumps(result), 1024),
                            },
                            redacted=True,
                        )
                    )
                    log.info(
                        "Tool call %s completed: %s", name, status, extra={"request_id": request_id}
                    )
                    if secret_token is not None:
                        active_secrets.reset(secret_token)
                    if task:
                        self.tasks.discard(task)
        return result
