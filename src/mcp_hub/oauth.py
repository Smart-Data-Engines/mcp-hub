"""Opaque OAuth tokens, PKCE and an OIDC bridge with verified ID tokens."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from .acl import ACL
from .config import Settings
from .models import HubError, Principal
from .store import Store, digest, dumps

_VERIFIER = re.compile(r"^[A-Za-z0-9._~-]{43,128}$", re.ASCII)
_CHALLENGE = re.compile(r"^[A-Za-z0-9_-]{43}$", re.ASCII)
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:+-]{0,254}$", re.ASCII)


class OAuthError(HubError):
    def __init__(self, code: str, description: str, status: int = 400):
        super().__init__(description, status, code=code)


def challenge(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


def verify_pkce(verifier: str, expected: str) -> bool:
    return bool(
        _VERIFIER.fullmatch(verifier) and hmac.compare_digest(challenge(verifier), expected)
    )


def redirect_origin(uri: str) -> str:
    """Validate a callback and return an ASCII origin safe for a CSP source."""
    parsed = urlsplit(uri)
    if not (
        len(uri) <= 2048
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
        and "*" not in uri
        and (
            parsed.scheme == "https"
            or (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})
        )
    ):
        raise ValueError("Invalid OAuth redirect URI")
    host = parsed.hostname.encode("idna").decode("ascii")
    if ":" in host:
        host = "[" + host + "]"
    port = parsed.port
    origin = parsed.scheme + "://" + host + (":" + str(port) if port is not None else "")
    if not re.fullmatch(r"https?://(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\])(?::[0-9]{1,5})?", origin):
        raise ValueError("Invalid OAuth redirect hostname")
    return origin


def valid_redirect(uri: str) -> bool:
    try:
        return bool(redirect_origin(uri))
    except (ValueError, UnicodeError):
        return False


CONSOLE_CLIENT_ID = "mcp-hub-admin"


class OAuth:
    def __init__(self, store: Store, settings: Settings, acl: ACL, client: httpx.AsyncClient):
        self.store, self.settings, self.acl, self.http = store, settings, acl, client
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
        self._hash_slots = asyncio.Semaphore(2)
        self._discovery: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self._jwks_at = 0.0

    async def initialize(self) -> None:
        await self.store.put(
            "oauth:client:" + CONSOLE_CLIENT_ID,
            {
                "client_id": CONSOLE_CLIENT_ID,
                "client_name": "MCP Hub console",
                "redirect_uris": [self.settings.hub_public_url + "/admin/"],
                "grant_types": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_method": "none",
                "management_allowed": True,
            },
        )

    def metadata(self) -> dict[str, Any]:
        public = self.settings.hub_public_url
        return {
            "issuer": public,
            "authorization_endpoint": public + "/authorize",
            "token_endpoint": public + "/token",
            "registration_endpoint": public + "/oauth/register",
            "revocation_endpoint": public + "/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": [
                "none",
                "client_secret_post",
                "client_secret_basic",
            ],
            "scopes_supported": ["mcp"],
        }

    def allows_resource(self, resource: str) -> bool:
        if resource == self.settings.resource:
            return True
        prefix = self.settings.resource + "/"
        return resource.startswith(prefix) and bool(
            re.fullmatch(r"[A-Za-z0-9_-]{1,64}", resource[len(prefix) :], flags=re.ASCII)
        )

    async def register_client(
        self, payload: dict[str, Any], *, bot: bool = False
    ) -> dict[str, Any]:
        redirects = payload.get("redirect_uris", [])
        if (
            not isinstance(redirects, list)
            or len(redirects) > 10
            or any(not isinstance(uri, str) or not valid_redirect(uri) for uri in redirects)
        ):
            raise OAuthError(
                "invalid_redirect_uri", "Redirect URIs must be HTTPS or HTTP loopback URLs"
            )
        if not bot and not redirects:
            raise OAuthError("invalid_client_metadata", "At least one redirect_uri is required")
        grants = payload.get("grant_types", ["authorization_code", "refresh_token"])
        if (
            not isinstance(grants, list)
            or any(not isinstance(grant, str) for grant in grants)
            or set(grants)
            - ({"client_credentials"} if bot else {"authorization_code", "refresh_token"})
        ):
            raise OAuthError(
                "invalid_client_metadata", "Bot clients must be created by an administrator"
            )
        method = payload.get("token_endpoint_auth_method", "client_secret_post" if bot else "none")
        if (
            not isinstance(method, str)
            or method not in {"none", "client_secret_post", "client_secret_basic"}
            or (bot and method == "none")
        ):
            raise OAuthError("invalid_client_metadata", "Unsupported client authentication method")
        name = payload.get("client_name", "MCP client")
        if not isinstance(name, str) or not 1 <= len(name) <= 128:
            raise OAuthError("invalid_client_metadata", "client_name must contain 1–128 characters")
        client_id = secrets.token_urlsafe(24)
        data = {
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": redirects,
            "grant_types": grants,
            "response_types": ["code"] if not bot else [],
            "token_endpoint_auth_method": method,
            "client_id_issued_at": int(time.time()),
        }
        management = payload.get("management_allowed", False)
        if not isinstance(management, bool) or (management and not bot):
            raise OAuthError(
                "invalid_client_metadata",
                "Management API access requires explicit administrator registration",
            )
        data["management_allowed"] = management
        secret = secrets.token_urlsafe(32) if method != "none" else None
        stored = dict(data)
        if secret:
            async with self._hash_slots:
                stored["secret_hash"] = await asyncio.to_thread(self.hasher.hash, secret)
        await self.store.put("oauth:client:" + client_id, stored)
        if bot:
            principal = Principal(
                id="bot_" + client_id, username=name, kind="bot", client_id=client_id
            )
            await self.acl.provision(principal)
        return {
            **data,
            **({"client_secret": secret, "client_secret_expires_at": 0} if secret else {}),
        }

    async def client(
        self, client_id: str, secret: str = "", *, method: str | None = None
    ) -> dict[str, Any]:
        client = await self.store.get("oauth:client:" + client_id)
        if not client:
            raise OAuthError("invalid_client", "Unknown client", 401)
        expected = client.get("token_endpoint_auth_method", "none")
        if method is not None and expected != method:
            raise OAuthError("invalid_client", "Wrong client authentication method", 401)
        if expected != "none":
            try:
                async with self._hash_slots:
                    await asyncio.to_thread(self.hasher.verify, client["secret_hash"], secret)
            except (VerificationError, KeyError) as exc:
                raise OAuthError("invalid_client", "Invalid client credentials", 401) from exc
        return client

    async def _issue(
        self,
        principal: Principal,
        client_id: str,
        *,
        consume_key: str | None = None,
        expected: str = "",
        management: bool | None = None,
    ) -> dict[str, Any]:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        access_key, refresh_key = (
            "oauth:access:" + digest(access),
            "oauth:refresh:" + digest(refresh),
        )
        principal = principal.model_copy(
            update={
                "client_id": client_id,
                "management": principal.management if management is None else management,
            }
        )
        index = f"oauth:principal:{digest(principal.id)}:{client_id}"
        clients_index = f"oauth:principal:{digest(principal.id)}:_clients"
        data = {
            "principal": principal.model_dump(),
            "client_id": client_id,
            "resource": self.settings.resource,
        }
        result = await self.store.script(
            """
            if ARGV[1]=='1' and redis.call('GET',KEYS[1])~=ARGV[2] then return 0 end
            if ARGV[1]=='1' then redis.call('DEL',KEYS[1]) end
            for _,key in ipairs(redis.call('SMEMBERS',KEYS[4])) do redis.call('DEL',key) end
            redis.call('DEL',KEYS[4])
            redis.call('SET',KEYS[2],ARGV[3],'EX',ARGV[5]); redis.call('SET',KEYS[3],ARGV[4],'EX',ARGV[6])
            redis.call('SADD',KEYS[4],KEYS[2],KEYS[3]); redis.call('EXPIRE',KEYS[4],ARGV[6])
            redis.call('SADD',KEYS[5],KEYS[4]); redis.call('EXPIRE',KEYS[5],ARGV[6]); return 1
        """,
            [consume_key or "oauth:_no-consume", access_key, refresh_key, index, clients_index],
            [
                "1" if consume_key else "0",
                expected,
                dumps({**data, "partner": self.store.key(refresh_key)}),
                dumps({**data, "partner": self.store.key(access_key)}),
                self.settings.access_token_ttl,
                self.settings.refresh_token_ttl,
            ],
        )
        if not result:
            raise OAuthError("invalid_grant", "The code or refresh token was already consumed")
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.settings.access_token_ttl,
            "refresh_token": refresh,
            "scope": "mcp",
        }

    async def code(self, principal: Principal, authorization: dict[str, Any]) -> str:
        code = secrets.token_urlsafe(32)
        await self.store.put(
            "oauth:code:" + digest(code),
            {**authorization, "principal": principal.model_dump()},
            ttl=60,
        )
        return code

    async def exchange(
        self, params: dict[str, str], *, basic: tuple[str, str] | None = None
    ) -> dict[str, Any]:
        client_id = basic[0] if basic else params.get("client_id", "")
        client = await self.client(
            client_id,
            basic[1] if basic else params.get("client_secret", ""),
            method="client_secret_basic"
            if basic
            else ("client_secret_post" if params.get("client_secret") else "none"),
        )
        grant = params.get("grant_type", "")
        if grant not in client.get("grant_types", []):
            raise OAuthError("unauthorized_client", "This client cannot use that grant")
        if not self.allows_resource(params.get("resource", self.settings.resource)):
            raise OAuthError("invalid_target", "Token audience must be this hub's MCP resource")
        if params.get("scope", "mcp") != "mcp":
            raise OAuthError("invalid_scope", "Only the mcp scope is supported")
        if grant == "authorization_code":
            key = "oauth:code:" + digest(params.get("code", ""))
            raw = await self.store.redis.get(self.store.key(key))
            if raw is None:
                raise OAuthError("invalid_grant", "Code expired or was already consumed")
            code = json.loads(raw)
            if (
                code["client_id"] != client_id
                or code["redirect_uri"] != params.get("redirect_uri")
                or not verify_pkce(params.get("code_verifier", ""), code["code_challenge"])
            ):
                raise OAuthError(
                    "invalid_grant", "Code, redirect URI or PKCE verifier does not match"
                )
            return await self._issue(
                Principal.model_validate(code["principal"]),
                client_id,
                consume_key=key,
                expected=raw,
                management=bool(client.get("management_allowed")),
            )
        if grant == "refresh_token":
            key = "oauth:refresh:" + digest(params.get("refresh_token", ""))
            raw = await self.store.redis.get(self.store.key(key))
            data = json.loads(raw) if raw else None
            if raw is None or not data or data["client_id"] != client_id:
                raise OAuthError(
                    "invalid_grant", "Refresh token is invalid or belongs to another client"
                )
            return await self._issue(
                Principal.model_validate(data["principal"]),
                client_id,
                consume_key=key,
                expected=raw,
                management=bool(client.get("management_allowed")),
            )
        if grant == "client_credentials":
            principal = Principal(
                id="bot_" + client_id,
                username=client["client_name"],
                kind="bot",
                client_id=client_id,
            )
            await self.acl.provision(principal)
            return await self._issue(
                principal, client_id, management=bool(client.get("management_allowed"))
            )
        raise OAuthError("unsupported_grant_type", "Unsupported grant_type")

    async def validate_token(self, token: str) -> Principal | None:
        if not 32 <= len(token) <= 512:
            return None
        data = await self.store.get("oauth:access:" + digest(token))
        if not data or data.get("resource") != self.settings.resource:
            return None
        return Principal.model_validate(data["principal"])

    async def revoke(self, token: str, client_id: str) -> None:
        for kind in ("access", "refresh"):
            await self.store.script(
                """
                local value=redis.call('GET',KEYS[1]); if not value then return 0 end
                local data=cjson.decode(value); if data.client_id~=ARGV[1] then return 0 end
                redis.call('DEL',KEYS[1]); if data.partner then redis.call('DEL',data.partner) end; return 1
            """,
                [f"oauth:{kind}:" + digest(token)],
                [client_id],
            )

    async def revoke_principal(self, principal_id: str) -> None:
        await self.store.script(
            """
            for _,index in ipairs(redis.call('SMEMBERS',KEYS[1])) do
                for _,key in ipairs(redis.call('SMEMBERS',index)) do redis.call('DEL',key) end
                redis.call('DEL',index)
            end
            return redis.call('DEL',KEYS[1])
        """,
            [f"oauth:principal:{digest(principal_id)}:_clients"],
        )

    async def discovery(self) -> dict[str, Any]:
        if (
            not self.settings.idp_client_id
            or not self.settings.idp_client_secret
            or not self.settings.idp_issuer
        ):
            raise HubError(
                "Human sign-in is not configured; set IDP_ISSUER, IDP_CLIENT_ID and IDP_CLIENT_SECRET",
                503,
            )
        if self._discovery is None:
            discovery_base = self.settings.idp_backchannel_url or self.settings.idp_issuer
            response = await self.http.get(
                discovery_base.rstrip("/") + "/.well-known/openid-configuration", timeout=10
            )
            response.raise_for_status()
            data = response.json()
            if data.get("issuer") != self.settings.idp_issuer:
                raise HubError("OIDC discovery issuer does not match IDP_ISSUER", 502)
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if (
                    not data.get(key, "").startswith("https://")
                    and self.settings.environment == "production"
                ):
                    raise HubError("OIDC endpoints must use HTTPS in production", 502)
            if self.settings.idp_backchannel_url:
                for key in ("token_endpoint", "jwks_uri"):
                    endpoint = urlsplit(data[key])
                    data[key] = (
                        self.settings.idp_backchannel_url.rstrip("/")
                        + endpoint.path
                        + ("?" + endpoint.query if endpoint.query else "")
                    )
                if (
                    self.settings.environment == "production"
                    and not self.settings.idp_backchannel_url.startswith("https://")
                ):
                    raise HubError("OIDC backchannel must use HTTPS in production", 502)
            self._discovery = data
        return self._discovery

    async def authorize(self, params: dict[str, str], browser: str) -> str:
        client_id = params.get("client_id", "")
        client = await self.store.get("oauth:client:" + client_id)
        if not client or params.get("redirect_uri") not in client.get("redirect_uris", []):
            raise OAuthError("invalid_request", "Unknown client or redirect URI")
        if (
            params.get("response_type") != "code"
            or params.get("code_challenge_method") != "S256"
            or not _CHALLENGE.fullmatch(params.get("code_challenge", ""))
        ):
            raise OAuthError(
                "invalid_request", "Authorization requires response_type=code and PKCE S256"
            )
        if (
            not self.allows_resource(params.get("resource", self.settings.resource))
            or params.get("scope", "mcp") != "mcp"
        ):
            raise OAuthError("invalid_target", "Unsupported resource or scope")
        if len(params.get("state", "")) > 2048:
            raise OAuthError("invalid_request", "State is too long")
        discovery = await self.discovery()
        state, nonce, verifier = (
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(48),
        )
        await self.store.put(
            "oauth:state:" + digest(state),
            {
                "authorization": {
                    key: params[key]
                    for key in ("client_id", "redirect_uri", "code_challenge", "state")
                    if key in params
                },
                "browser": digest(browser),
                "nonce": nonce,
                "verifier": verifier,
            },
            ttl=300,
        )
        callback = f"{self.settings.hub_public_url}/oauth/{self.settings.idp_provider}/callback"
        return (
            discovery["authorization_endpoint"]
            + "?"
            + urlencode(
                {
                    "response_type": "code",
                    "client_id": self.settings.idp_client_id,
                    "redirect_uri": callback,
                    "scope": self.settings.idp_scopes,
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": challenge(verifier),
                    "code_challenge_method": "S256",
                }
            )
        )

    async def callback(
        self, state: str, code: str, browser: str
    ) -> tuple[Principal, dict[str, Any]]:
        key = "oauth:state:" + digest(state)
        raw = await self.store.redis.get(self.store.key(key))
        data = json.loads(raw) if raw else None
        if not data or not hmac.compare_digest(data["browser"], digest(browser)):
            raise OAuthError("invalid_request", "Invalid, expired or unrelated browser login state")
        consumed = await self.store.script(
            "if redis.call('GET',KEYS[1])==ARGV[1] then redis.call('DEL',KEYS[1]); return 1 end return 0",
            [key],
            [raw],
        )
        if not consumed:
            raise OAuthError("invalid_request", "Login state was already consumed")
        discovery = await self.discovery()
        client_auth = (
            {"client_secret": self.settings.idp_client_secret}
            if self.settings.idp_token_auth_method == "client_secret_post"
            else {}
        )
        response = await self.http.post(
            discovery["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": self.settings.idp_client_id,
                **client_auth,
                "redirect_uri": f"{self.settings.hub_public_url}/oauth/{self.settings.idp_provider}/callback",
                "code_verifier": data["verifier"],
            },
            timeout=10,
            auth=httpx.BasicAuth(self.settings.idp_client_id, self.settings.idp_client_secret)
            if self.settings.idp_token_auth_method == "client_secret_basic"
            else httpx.Auth(),
        )
        response.raise_for_status()
        tokens = response.json()
        id_token = tokens.get("id_token", "")
        try:
            header = jwt.get_unverified_header(id_token)
            if header.get("alg") not in {"RS256", "ES256"}:
                raise ValueError("Unsupported signature")
            if (
                self._jwks is None
                or time.monotonic() - self._jwks_at > 300
                or not any(key.get("kid") == header.get("kid") for key in self._jwks["keys"])
            ):
                jwks_response = await self.http.get(discovery["jwks_uri"], timeout=10)
                jwks_response.raise_for_status()
                self._jwks, self._jwks_at = jwks_response.json(), time.monotonic()
            candidates = [
                key
                for key in self._jwks["keys"]
                if key.get("kid") == header.get("kid") and key.get("use", "sig") == "sig"
            ]
            if len(candidates) != 1:
                raise ValueError("Unknown signing key")
            claims = jwt.decode(
                id_token,
                jwt.PyJWK.from_dict(candidates[0]).key,
                algorithms=[header["alg"]],
                audience=self.settings.idp_client_id,
                issuer=self.settings.idp_issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
                leeway=30,
            )
            if not hmac.compare_digest(str(claims.get("nonce", "")), data["nonce"]):
                raise ValueError("Invalid nonce")
            if (
                isinstance(claims["aud"], list)
                and len(claims["aud"]) > 1
                and claims.get("azp") != self.settings.idp_client_id
            ):
                raise ValueError("Invalid authorized party")
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            raise OAuthError(
                "access_denied", "The identity provider returned an invalid ID token", 401
            ) from exc
        email = str(claims.get("email", ""))
        if self.settings.idp_allowed_domains:
            allowed = {
                domain.strip().lower() for domain in self.settings.idp_allowed_domains.split(",")
            }
            if (
                claims.get("email_verified") is not True
                or email.rpartition("@")[2].lower() not in allowed
                or (
                    self.settings.idp_provider == "google"
                    and str(claims.get("hd", "")).lower() not in allowed
                )
            ):
                raise OAuthError(
                    "access_denied", "A verified company email address is required", 403
                )
        username = str(
            claims.get(self.settings.idp_username_claim) or claims.get("email") or claims["sub"]
        )
        if not _USERNAME.fullmatch(username):
            raise OAuthError(
                "access_denied",
                "The configured username claim is not a safe identity; use a verified email or subject",
                403,
            )
        principal = Principal(
            id="user_" + digest(self.settings.idp_issuer + "\0" + str(claims["sub"])),
            username=username,
        )
        await self.acl.provision(principal)
        await self.acl.apply_admin_policy(
            self.settings.admin_emails,
            principal=principal,
            verified_email=email if claims.get("email_verified") is True else "",
        )
        return principal, data["authorization"]


def redirect_with_code(authorization: dict[str, Any], code: str) -> str:
    separator = "&" if "?" in authorization["redirect_uri"] else "?"
    return (
        authorization["redirect_uri"]
        + separator
        + urlencode({"code": code, "state": authorization.get("state", "")})
    )


def redirect_with_error(authorization: dict[str, Any], error: str) -> str:
    separator = "&" if "?" in authorization["redirect_uri"] else "?"
    return (
        authorization["redirect_uri"]
        + separator
        + urlencode({"error": error, "state": authorization.get("state", "")})
    )
