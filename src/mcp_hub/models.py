"""Validated public domain objects; secrets are excluded from representations."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, FiniteFloat

Category = Literal["read", "write", "destructive"]
ALL_CAPS: set[Category] = {"read", "write", "destructive"}
NAME = re.compile(r"^[a-z0-9_-]{1,64}$", re.ASCII)
RESERVED_ARGS = frozenset({"credentials", "_hub_username", "_hub_user_id", "_hub_principal"})


class HubError(Exception):
    def __init__(
        self, message: str, status: int = 400, *, code: str = "error", retry_after: int = 0
    ):
        super().__init__(message)
        self.message, self.status, self.code, self.retry_after = message, status, code, retry_after


class Principal(BaseModel):
    id: str
    username: str
    kind: Literal["human", "bot", "anonymous"] = "human"
    client_id: str = ""
    management: bool = False

    @property
    def may_manage(self) -> bool:
        return self.management or self.client_id == "mcp-hub-admin"


class ServerDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    owner: str
    description: str = Field(default="", max_length=1000)
    visibility: Literal["private", "shared", "public"] = "private"
    shared_with: list[str] = Field(default_factory=list, max_length=100)
    autostart: bool = False
    status: Literal["stopped", "starting", "stopping", "running", "error"] = "stopped"
    code_version: str = ""
    user_env_fields: list[str] = Field(default_factory=list)
    pinned_ref: str = ""
    memory_mb: int = Field(default=512, ge=64, le=2048)
    cpus: float = Field(default=1.0, ge=0.1, le=2.0)
    policy: Literal["both", "global_only", "user_only"] = "both"
    idempotency: bool = True
    approval_required: bool = False
    approval_four_eyes: bool = False
    call_timeout: FiniteFloat | None = Field(default=None, gt=0)
    read_timeout: FiniteFloat | None = Field(default=None, gt=0)
    error: str = ""


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    url: str = Field(max_length=2048)
    code_version: str = Field(default="", max_length=128)


def visible(definition: dict[str, Any], principal: Principal, *, admin: bool = False) -> bool:
    return bool(
        admin
        or definition.get("owner") == principal.id
        or definition.get("visibility", "public") == "public"
        or (
            definition.get("visibility") == "shared"
            and principal.id in definition.get("shared_with", [])
        )
    )
