"""HTTP boundary: authentication, body bounds, safe errors and OAuth discovery."""

from __future__ import annotations

import base64
import logging
import secrets
import time
from typing import Any
from urllib.parse import quote

from opentelemetry import context as otel_context
from opentelemetry import trace
from pydantic import ValidationError
from redis.exceptions import RedisError
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .arguments import validate_json
from .auth_pages import consent_page, expired_consent_page
from .gateway import RequestContext, request_context
from .models import HubError, Principal
from .oauth import (
    CONSOLE_CLIENT_ID,
    OAuthError,
    redirect_origin,
    redirect_with_code,
    redirect_with_error,
)
from .store import digest

log = logging.getLogger(__name__)
tracer = trace.get_tracer("mcp_hub.http")


def error_response(exc: HubError) -> JSONResponse:
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else {}
    if isinstance(exc, OAuthError):
        return JSONResponse(
            {"error": exc.code, "error_description": exc.message}, exc.status, headers=headers
        )
    return JSONResponse({"error": exc.message}, exc.status, headers=headers)


async def body(request: Request) -> dict[str, Any]:
    try:
        value = await request.json()
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HubError("Request body must contain valid JSON") from exc
    if not isinstance(value, dict):
        raise HubError("Request body must be a JSON object")
    validate_json(value)
    return value


def context(request: Request) -> RequestContext:
    value = request.scope.get("hub.context")
    if value is None:
        raise HubError("Authentication required", 401)
    return value


class Boundary:
    def __init__(self, app, hub, authenticate: bool = True):
        self.app, self.hub, self.authenticate = app, hub, authenticate

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope["path"]
        route = (
            "mcp"
            if path.startswith("/mcp")
            else "api"
            if path.startswith(("/admin/api", "/credentials"))
            else "oauth"
            if path.startswith(("/oauth", "/authorize", "/token", "/.well-known"))
            else "probes"
            if path in {"/health", "/ready", "/metrics"}
            else "console"
            if path.startswith("/admin")
            else "other"
        )
        method = (
            scope["method"]
            if scope["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
            else "OTHER"
        )
        began = time.monotonic()
        self.hub.metrics.http_inflight.labels(route).inc()
        span = tracer.start_span(
            "mcp.request" if route == "mcp" else "http.request",
            attributes={"http.request.method": method, "http.route": route},
        )
        span_token = otel_context.attach(trace.set_span_in_context(span))
        response_status = 500
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        settings = self.hub.settings
        ctx = None
        token = None
        started = False

        async def safe_send(message):
            nonlocal started, response_status
            if message["type"] == "http.response.start":
                started = True
                response_status = message["status"]
                form_action = b"'self'"
                if target := scope.get("hub.oauth.form_action"):
                    form_action += b" " + target.encode("ascii")
                security = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action "
                        + form_action,
                    ),
                    (b"cache-control", b"no-store"),
                ]
                if settings.secure_cookies:
                    security.append(
                        (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
                    )
                if ctx:
                    security.extend(
                        [
                            (b"x-request-id", ctx.request_id.encode()),
                            (b"x-hub-catalog-version", str(ctx.catalog_version).encode()),
                        ]
                    )
                    if ctx.retry_after:
                        security.append((b"retry-after", str(ctx.retry_after).encode()))
                    security.append(
                        (
                            b"x-hub-overhead-ms",
                            f"{max(0.0, time.monotonic() - began - ctx.upstream_seconds) * 1000:.3f}".encode(),
                        )
                    )
                message["headers"] = list(message.get("headers", [])) + security
            await send(message)

        consumed = 0

        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get("body", b""))
            if consumed > settings.max_request_bytes:
                raise HubError("Request body exceeds the configured byte limit", 413)
            return message

        try:
            if int(headers.get(b"content-length", b"0")) > settings.max_request_bytes:
                raise HubError("Request body exceeds the configured byte limit", 413)
            if self.authenticate and path.startswith(("/mcp", "/admin/api", "/credentials")):
                authorization = headers.get(b"authorization", b"").decode("latin-1")
                if sum(key.lower() == b"authorization" for key, _ in scope.get("headers", [])) > 1:
                    raise HubError("Multiple Authorization headers are not accepted", 401)
                if authorization.startswith("Bearer "):
                    principal = await self.hub.oauth.validate_token(authorization[7:])
                elif not authorization and path == "/mcp/public" and settings.hub_anonymous_enabled:
                    principal = Principal(id="anonymous", username="anonymous", kind="anonymous")
                else:
                    principal = None
                if not principal:
                    self.hub.metrics.auth.labels(
                        "mcp" if path.startswith("/mcp") else "api", "invalid_token"
                    ).inc()
                    response = JSONResponse(
                        {"error": "Authentication required"},
                        401,
                        headers={
                            "WWW-Authenticate": f'Bearer resource_metadata="{settings.hub_public_url}/.well-known/oauth-protected-resource{quote(path if path.startswith("/mcp") else "/mcp", safe="/")}", scope="mcp"'
                        },
                    )
                    await response(scope, receive, safe_send)
                    return
                if (
                    path.startswith("/admin/api")
                    and path != "/admin/api/whoami"
                    and not principal.may_manage
                ):
                    self.hub.metrics.auth.labels("api", "management_client_required").inc()
                    raise HubError(
                        "This token is for MCP tools only. Sign in through the Hub console or use an explicitly enabled management client.",
                        403,
                    )
                ctx = RequestContext(
                    principal,
                    ip=scope.get("client", ("", 0))[0],
                    credentials_header=headers.get(b"x-hub-credentials", b"").decode("utf-8")
                    or None,
                )
                scope["hub.context"] = ctx
                token = request_context.set(ctx)
            await self.app(scope, bounded_receive, safe_send)
        except HubError as exc:
            if not started:
                await error_response(exc)(scope, receive, safe_send)
        except ValidationError:
            if not started:
                await JSONResponse(
                    {"error": "Invalid request fields; consult the API schema"}, 422
                )(scope, receive, safe_send)
        except (RedisError, ConnectionError):
            if not started:
                await JSONResponse({"error": "State store unavailable; request denied"}, 503)(
                    scope, receive, safe_send
                )
        except (ValueError, UnicodeError):
            if not started:
                await JSONResponse({"error": "Invalid request encoding or field value"}, 400)(
                    scope, receive, safe_send
                )
        except Exception as exc:
            log.error(
                "HTTP handler failed: %s",
                type(exc).__name__,
                extra={"request_id": ctx.request_id if ctx else ""},
            )
            if not started:
                await JSONResponse(
                    {"error": "Internal hub error; use the request ID to investigate"}, 500
                )(scope, receive, safe_send)
        finally:
            self.hub.metrics.http_requests.labels(method, route, str(response_status)).inc()
            self.hub.metrics.http_duration.labels(method, route).observe(time.monotonic() - began)
            self.hub.metrics.http_inflight.labels(route).dec()
            self.hub.metrics.payload.labels("request").observe(consumed)
            span.set_attribute("http.response.status_code", response_status)
            if ctx:
                span.set_attribute("hub.request_id", ctx.request_id)
            otel_context.detach(span_token)
            span.end()
            if token is not None:
                request_context.reset(token)


def basic_credentials(request: Request) -> tuple[str, str] | None:
    authorization = request.headers.get("authorization", "")
    if not authorization:
        return None
    if not authorization.startswith("Basic "):
        raise OAuthError("invalid_client", "Use HTTP Basic client authentication", 401)
    try:
        username, password = (
            base64.b64decode(authorization[6:], validate=True).decode().split(":", 1)
        )
        from urllib.parse import unquote

        return unquote(username), unquote(password)
    except (ValueError, UnicodeError) as exc:
        raise OAuthError("invalid_client", "Invalid Basic authentication", 401) from exc


async def _auth_rate(request: Request, endpoint: str) -> None:
    hub = request.app.state.hub
    ip = request.client.host if request.client else "unknown"
    allowed, retry = await hub.store.rate(
        "auth:" + endpoint + ":" + digest(ip), hub.settings.auth_rate_limit, 60
    )
    if not allowed:
        raise HubError("Authentication rate limit reached", 429, retry_after=retry)


def oauth_routes() -> list[Route]:
    async def metadata(request: Request) -> Response:
        return JSONResponse(request.app.state.hub.oauth.metadata())

    async def resource(request: Request) -> Response:
        settings = request.app.state.hub.settings
        path = request.path_params.get("path", "mcp")
        resource_url = (
            settings.hub_public_url + "/" + path if path.startswith("mcp/") else settings.resource
        )
        return JSONResponse(
            {
                "resource": resource_url,
                "authorization_servers": [settings.hub_public_url],
                "scopes_supported": ["mcp"],
                "bearer_methods_supported": ["header"],
            }
        )

    async def register(request: Request) -> Response:
        await _auth_rate(request, "register")
        data = await request.app.state.hub.oauth.register_client(await body(request))
        return JSONResponse(data, 201)

    async def authorize(request: Request) -> Response:
        await _auth_rate(request, "authorize")
        hub = request.app.state.hub
        browser = secrets.token_urlsafe(32)
        target = await hub.oauth.authorize(dict(request.query_params), browser)
        response = RedirectResponse(target, 302)
        response.set_cookie(
            "hub_login",
            browser,
            max_age=300,
            httponly=True,
            secure=hub.settings.secure_cookies,
            samesite="lax",
            path="/",
        )
        return response

    async def callback(request: Request) -> Response:
        await _auth_rate(request, "callback")
        hub = request.app.state.hub
        if request.path_params["provider"] != hub.settings.idp_provider:
            raise HubError("Unknown identity provider", 404)
        principal, authorization = await hub.oauth.callback(
            request.query_params.get("state", ""),
            request.query_params.get("code", ""),
            request.cookies.get("hub_login", ""),
        )
        client = await hub.store.get("oauth:client:" + authorization["client_id"])
        if not client:
            raise OAuthError(
                "invalid_client", "Application registration expired; start sign-in again"
            )
        response: Response
        if authorization["client_id"] == CONSOLE_CLIENT_ID:
            console_redirect = hub.settings.hub_public_url + "/admin/"
            if not (
                client.get("client_id") == CONSOLE_CLIENT_ID
                and authorization["redirect_uri"] == console_redirect
                and client.get("redirect_uris") == [console_redirect]
                and client.get("token_endpoint_auth_method") == "none"
                and client.get("management_allowed") is True
            ):
                raise OAuthError(
                    "invalid_request", "Console configuration changed; start sign-in again"
                )
            code = await hub.oauth.code(principal, authorization)
            response = RedirectResponse(redirect_with_code(authorization, code), 302)
            response.delete_cookie("hub_login")
        else:
            request.scope["hub.oauth.form_action"] = redirect_origin(authorization["redirect_uri"])
            consent = secrets.token_urlsafe(32)
            await hub.store.put(
                "oauth:consent:" + digest(consent),
                {
                    "principal": principal.model_dump(),
                    "authorization": authorization,
                    "browser": digest(request.cookies.get("hub_login", "")),
                },
                ttl=300,
            )
            response = consent_page(
                client["client_name"], principal.username, authorization["redirect_uri"], consent
            )
        session, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        await hub.store.put(
            "oauth:ui:" + digest(session), {"principal_id": principal.id, "csrf": csrf}, ttl=3600
        )
        response.set_cookie(
            "hub_ui",
            session,
            max_age=3600,
            httponly=True,
            secure=hub.settings.secure_cookies,
            samesite="strict",
            path="/",
        )
        return response

    async def consent(request: Request) -> Response:
        hub = request.app.state.hub
        form = await request.form()
        key = "oauth:consent:" + digest(str(form.get("consent", "")))
        data = await hub.store.get(key)
        import hmac

        if not data or not hmac.compare_digest(
            data["browser"], digest(request.cookies.get("hub_login", ""))
        ):
            return expired_consent_page()
        request.scope["hub.oauth.form_action"] = redirect_origin(
            data["authorization"]["redirect_uri"]
        )
        raw = await hub.store.redis.getdel(hub.store.key(key))
        if not raw:
            return expired_consent_page()
        if form.get("decision") != "allow":
            response = RedirectResponse(
                redirect_with_error(data["authorization"], "access_denied"), 302
            )
        else:
            code = await hub.oauth.code(
                Principal.model_validate(data["principal"]), data["authorization"]
            )
            response = RedirectResponse(redirect_with_code(data["authorization"], code), 302)
        response.delete_cookie("hub_login")
        return response

    async def token(request: Request) -> Response:
        await _auth_rate(request, "token")
        params = {key: str(value) for key, value in (await request.form()).items()}
        return JSONResponse(
            await request.app.state.hub.oauth.exchange(params, basic=basic_credentials(request))
        )

    async def revoke(request: Request) -> Response:
        await _auth_rate(request, "revoke")
        params = {key: str(value) for key, value in (await request.form()).items()}
        basic = basic_credentials(request)
        client_id = basic[0] if basic else params.get("client_id", "")
        hub = request.app.state.hub
        await hub.oauth.client(
            client_id,
            basic[1] if basic else params.get("client_secret", ""),
            method="client_secret_basic"
            if basic
            else ("client_secret_post" if params.get("client_secret") else "none"),
        )
        await hub.oauth.revoke(params.get("token", ""), client_id)
        return Response(status_code=200)

    return [
        Route("/.well-known/oauth-authorization-server", metadata),
        Route("/.well-known/oauth-protected-resource", resource),
        Route("/.well-known/oauth-protected-resource/{path:path}", resource),
        Route("/oauth/register", register, methods=["POST"]),
        Route("/authorize", authorize),
        Route("/oauth/{provider}/callback", callback),
        Route("/oauth/consent", consent, methods=["POST"]),
        Route("/token", token, methods=["POST"]),
        Route("/oauth/revoke", revoke, methods=["POST"]),
    ]
