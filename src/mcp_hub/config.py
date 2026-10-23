"""Environment-only configuration with explicit, bounded numerical defaults."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from dotenv import load_dotenv

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Settings:
    store_url: str = field(default="", repr=False)
    credentials_encryption_key: str = field(default="", repr=False)
    hub_public_url: str = "http://localhost:8000"
    environment: str = "production"
    store_prefix: str = "hub:v1:"
    hub_registration_secret: str = field(default="", repr=False)
    hub_upstream_secret: str = field(default="", repr=False)
    hub_allow_insecure_registration: bool = False
    hub_allowed_register_hosts: str = ""
    idp_provider: str = "oidc"
    idp_issuer: str = ""
    idp_backchannel_url: str = ""
    idp_client_id: str = ""
    idp_client_secret: str = field(default="", repr=False)
    idp_token_auth_method: str = "client_secret_post"
    idp_username_claim: str = "preferred_username"
    idp_allowed_domains: str = ""
    idp_scopes: str = "openid profile email"
    admin_emails: str = ""
    access_token_ttl: int = 2_592_000
    refresh_token_ttl: int = 7_776_000
    auth_rate_limit: int = 10
    hub_tool_rate_limit: int = 300
    hub_tool_rate_window: int = 60
    hub_daily_call_budget: int = 0
    upstream_list_tools_timeout: float = 2.0
    upstream_call_tool_timeout: float = 600.0
    session_read_timeout: float = 90.0
    catalog_refresh_interval: float = 30.0
    registry_reconcile_interval: float = 15.0
    heartbeat_interval: int = 60
    circuit_breaker_threshold: int = 3
    circuit_breaker_base_backoff: float = 5.0
    max_response_chars: int = 65_536
    max_upstream_response_bytes: int = 8_388_608
    max_upstream_tools: int = 2000
    max_request_bytes: int = 1_048_576
    hub_secret_scrubbing_enabled: bool = True
    hub_provenance_footer: bool = True
    hub_anonymous_enabled: bool = False
    idempotency_ttl: int = 600
    approval_ttl: int = 900
    audit_spool_max_entries: int = 10_000
    audit_retention_days: int = 30
    audit_sink_url: str = ""
    audit_sink_user: str = ""
    audit_sink_password: str = field(default="", repr=False)
    shutdown_grace_period: float = 30.0
    guardrail_rules: str = "[]"
    enable_self_service: bool = False
    registry_backend: str = "github"
    registry_repository: str = ""
    registry_branch: str = "main"
    registry_token: str = field(default="", repr=False)
    registry_read_only: bool = False
    registry_local_path: str = ".local/registry.git"
    registry_git_remote: str = ""
    registry_ssh_key: str = ""
    registry_known_hosts: str = ""
    server_source_dir: str = ".local/servers"
    runtime_host_source_root: str = ""
    runtime_image: str = "mcp-hub-upstream:local"
    runtime_hub_container: str = "mcp-hub"
    network_state: str = "mcp-hub-state"
    network_ingress: str = "mcp-hub-ingress"
    network_upstream_prefix: str = "mcp-hub-upstream-"
    hub_bind_host: str = "127.0.0.1"
    trusted_proxy_ips: str = ""
    hub_port: int = 8000
    registration_port: int = 8001
    max_servers_per_owner: int = 10
    max_credential_bytes: int = 16384
    max_credential_services: int = 32
    max_credential_preferences: int = 64
    credential_write_rate_limit: int = 60
    max_oauth_clients: int = 1024
    oauth_registration_ttl: int = 3600
    max_audit_event_bytes: int = 8192
    max_approval_argument_bytes: int = 16384
    frontend_dir: str = "frontend/dist"
    otel_exporter_otlp_endpoint: str = ""
    hub_ca_bundle: str = ""
    hub_http_proxy: str = field(default="", repr=False)

    @classmethod
    def from_env(cls, *, dotenv: bool = True) -> Settings:
        if dotenv:
            load_dotenv(override=False)
        defaults = cls()
        values: dict[str, object] = {}
        for item in fields(cls):
            raw = os.environ.get(item.name.upper())
            if raw is None:
                continue
            default = getattr(defaults, item.name)
            try:
                if isinstance(default, bool):
                    if raw.lower() not in {"true", "false", "1", "0"}:
                        raise ValueError
                    values[item.name] = raw.lower() in {"true", "1"}
                elif isinstance(default, int):
                    values[item.name] = int(raw)
                    if values[item.name] < 0:  # type: ignore[operator]
                        raise ValueError
                    zero_allowed = {
                        "hub_tool_rate_limit",
                        "hub_daily_call_budget",
                        "max_response_chars",
                        "circuit_breaker_threshold",
                    }
                    if values[item.name] == 0 and item.name not in zero_allowed:
                        raise ValueError
                    if item.name in {"hub_port", "registration_port"} and int(raw) > 65535:
                        raise ValueError
                    if item.name == "max_response_chars" and 0 < int(raw) < 128:
                        raise ValueError
                elif isinstance(default, float):
                    value = float(raw)
                    if not 0 < value < float("inf"):
                        raise ValueError
                    values[item.name] = value
                else:
                    values[item.name] = raw
            except ValueError:
                values.pop(item.name, None)
                log.warning(
                    "Invalid numerical/boolean setting %s; using default", item.name.upper()
                )
        settings = cls(**values)  # type: ignore[arg-type]
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.access_token_ttl > self.refresh_token_ttl:
            raise ValueError("ACCESS_TOKEN_TTL must not outlive the refresh/revocation index")
        if self.environment not in {"production", "development"}:
            raise ValueError("ENVIRONMENT must be production or development")
        if not 1024 <= self.max_credential_bytes <= 65536:
            raise ValueError("MAX_CREDENTIAL_BYTES must be between 1024 and 65536")
        if not (
            1 <= self.max_credential_services <= 1024
            and 1 <= self.max_credential_preferences <= 1024
        ):
            raise ValueError("Personal credential/preference limits must be between 1 and 1024")
        if not 1 <= self.credential_write_rate_limit <= 1000:
            raise ValueError("CREDENTIAL_WRITE_RATE_LIMIT must be between 1 and 1000")
        if (
            not 1 <= self.max_oauth_clients <= 10000
            or not 60 <= self.oauth_registration_ttl <= 86400
        ):
            raise ValueError("OAuth registration count or lifetime is outside its supported bounds")
        if (
            not 2048 <= self.max_audit_event_bytes <= 65536
            or not 1024 <= self.max_approval_argument_bytes <= 65536
        ):
            raise ValueError("Audit/approval byte limits are outside their supported bounds")
        if not self.store_url.startswith(("redis://", "rediss://")):
            raise ValueError("STORE_URL must identify a Redis server")
        if not self.credentials_encryption_key:
            raise ValueError("CREDENTIALS_ENCRYPTION_KEY is required")
        for key in self.credentials_encryption_key.split(","):
            Fernet(key.strip().encode())
        public = urlsplit(self.hub_public_url)
        if (
            public.scheme not in {"http", "https"}
            or not public.hostname
            or public.query
            or public.fragment
            or public.username
        ):
            raise ValueError("HUB_PUBLIC_URL must be an HTTP(S) origin")
        if public.path not in {"", "/"}:
            raise ValueError("HUB_PUBLIC_URL must not contain a path")
        self.hub_public_url = self.hub_public_url.rstrip("/")
        if self.environment == "production":
            if public.scheme != "https":
                raise ValueError("Production requires an HTTPS HUB_PUBLIC_URL")
            if not urlsplit(self.store_url).password:
                raise ValueError("Production requires an authenticated STORE_URL")
            if self.hub_allow_insecure_registration:
                raise ValueError("Insecure registration is development-only")
            if self.idp_issuer and not self.idp_issuer.startswith("https://"):
                raise ValueError("Production requires an HTTPS OIDC issuer")
        if self.idp_provider not in {
            "oidc",
            "google",
            "entra",
            "keycloak",
            "okta",
            "auth0",
            "gitlab",
        }:
            raise ValueError("Unsupported IDP_PROVIDER; use a supported preset or oidc")
        if self.registry_backend not in {"local", "github", "git"}:
            raise ValueError("REGISTRY_BACKEND must be local, github or git")
        if self.registry_backend == "git" and not self.registry_git_remote:
            raise ValueError("REGISTRY_GIT_REMOTE is required for the Git registry")
        if self.admin_emails and any(
            "@" not in email.strip() or any(c.isspace() for c in email.strip())
            for email in self.admin_emails.split(",")
        ):
            raise ValueError("ADMIN_EMAILS must contain verified email addresses")
        if self.idp_token_auth_method not in {"client_secret_post", "client_secret_basic"}:
            raise ValueError(
                "IDP_TOKEN_AUTH_METHOD must be client_secret_post or client_secret_basic"
            )
        if self.session_read_timeout >= self.upstream_call_tool_timeout:
            raise ValueError("SESSION_READ_TIMEOUT must be below UPSTREAM_CALL_TOOL_TIMEOUT")
        if not 5 <= self.shutdown_grace_period <= 300:
            raise ValueError("SHUTDOWN_GRACE_PERIOD must be between 5 and 300 seconds")
        if self.enable_self_service and (
            not self.hub_registration_secret or not self.hub_upstream_secret
        ):
            raise ValueError("Self-service requires registration and upstream secrets")
        if self.enable_self_service and self.hub_bind_host in {"0.0.0.0", "::", ""}:
            raise ValueError(
                "Self-service requires the control listener bound to the ingress interface"
            )

    @property
    def resource(self) -> str:
        return f"{self.hub_public_url}/mcp"

    @property
    def secure_cookies(self) -> bool:
        return self.hub_public_url.startswith("https://")

    @property
    def frontend_path(self) -> Path:
        return Path(self.frontend_dir).resolve()
