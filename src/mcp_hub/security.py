"""Credential encryption, secret redaction and declared tool capabilities."""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import traceback
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .models import RESERVED_ARGS, Category, HubError
from .store import dumps

MASK = "[REDACTED]"
active_secrets: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "secrets", default=()
)
_KEY = re.compile(r"password|passwd|secret|token|apikey|authorization|privatekey", re.ASCII)
_PLACEHOLDERS = {"", "example", "changeme", "placeholder", "null", "none", MASK.lower(), "********"}
# Bounded patterns: no nested repeats or unbounded wildcards on attacker input.
_PATTERNS = (
    re.compile(r"\b(?:ntn_|secret_)[A-Za-z0-9_-]{16,255}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,256}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,1024}\b"),
)
_URI = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s/:@]{1,256}:)([^\s@]{1,1024})(@)")
_BEARER = re.compile(r"(?i)(\bBearer\s{1,8})[A-Za-z0-9._~+/-]{8,4096}")
_ASSIGN = re.compile(
    r"""(?i)(\b(?:password|passwd|api[_-]?key|secret|access[_-]?token|refresh[_-]?token)\b["']?\s{0,8}[:=]\s{0,8}["']?)([^\s"',;}]{1,2048})"""
)


def secret_key(key: str) -> bool:
    return bool(_KEY.search(re.sub(r"[^a-z0-9]", "", key.lower())))


def secret_values(value: Any) -> tuple[str, ...]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"user", "username", "_hub_username", "_hub_user_id", "_hub_principal"}:
                continue
            if isinstance(item, str) and item.lower() not in _PLACEHOLDERS:
                for connection in _URI.finditer(item):
                    found.extend((connection[2], unquote(connection[2])))
                metadata = str(key).lower().rsplit("_", 1)[-1] in {
                    "url",
                    "uri",
                    "host",
                    "port",
                    "path",
                    "region",
                    "database",
                    "schema",
                    "timeout",
                }
                if secret_key(str(key)) or not metadata:
                    found.append(item)
            elif isinstance(item, (dict, list)):
                found.extend(secret_values(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(secret_values(item))
    return tuple(found)


def scrub_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    for secret in sorted(set(secrets + active_secrets.get()), key=len, reverse=True):
        if secret and secret != MASK:
            text = text.replace(secret, MASK)
    text = _URI.sub(lambda m: m[1] + MASK + m[3], text)
    text = _BEARER.sub(lambda m: m[1] + MASK, text)
    text = _ASSIGN.sub(lambda m: m[1] + (m[2] if m[2].lower() in _PLACEHOLDERS else MASK), text)
    for pattern in _PATTERNS:
        text = pattern.sub(MASK, text)
    return text


def scrub(value: Any, secrets: tuple[str, ...] = (), *, audit: bool = False) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if audit and key in RESERVED_ARGS:
                continue
            if secret_key(str(key)) and item is not None and str(item).lower() not in _PLACEHOLDERS:
                result[key] = MASK
            else:
                result[key] = scrub(item, secrets, audit=audit)
        return result
    if isinstance(value, list):
        return [scrub(item, secrets, audit=audit) for item in value]
    if isinstance(value, str):
        # TextContent frequently contains serialized JSON; apply key-aware rules there too.
        if value.lstrip().startswith(("{", "[")):
            try:
                return dumps(scrub(json.loads(value), secrets, audit=audit))
            except (ValueError, RecursionError):
                pass
        return scrub_text(value, secrets)
    return value


def cap_text(text: str, limit: int) -> str:
    if not limit or len(text) <= limit:
        return text
    notice = (
        f"\n[TRUNCATED: original {len(text)} characters. Narrow the query to retrieve the rest.]"
    )
    if len(notice) >= limit:
        return ("[TRUNCATED] " + str(len(text)))[:limit]
    return text[: limit - len(notice)] + notice


def category(tool: dict[str, Any]) -> tuple[Category, bool]:
    annotations = tool.get("annotations")
    if annotations is not None:
        if annotations.get("readOnlyHint") is True:
            return "read", True
        # MCP defaults destructiveHint to true when a mutating annotation omits it.
        if annotations.get("destructiveHint", True) is not False:
            return "destructive", True
        return "write", True
    # Names are not an authorization contract. MCP defaults unknown tools to mutating/destructive.
    return "destructive", False


def public_schema(schema: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(dumps(schema))
    for key in RESERVED_ARGS:
        result.get("properties", {}).pop(key, None)
    if "required" in result:
        result["required"] = [key for key in result["required"] if key not in RESERVED_ARGS]
    # Reject undeclared client keys; the hub injects its fields only after validation.
    result["additionalProperties"] = False
    return result


class Cipher:
    def __init__(self, keys: str):
        self.cipher = MultiFernet([Fernet(key.strip().encode()) for key in keys.split(",")])

    def encrypt(self, value: Any) -> str:
        return self.cipher.encrypt(dumps(value).encode()).decode()

    def decrypt(self, value: str) -> Any:
        try:
            return json.loads(self.cipher.decrypt(value.encode()))
        except (InvalidToken, ValueError) as exc:
            raise HubError(
                "Stored credentials cannot be decrypted; contact the administrator",
                503,
                code="decryption_failed",
            ) from exc

    def rotate(self, value: str) -> str:
        try:
            return self.cipher.rotate(value.encode()).decode()
        except InvalidToken as exc:
            raise HubError("Key rotation failed: missing decryption key", 503) from exc


class RedactingJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        try:
            raw_message = record.getMessage()
            message = (
                scrub_text(raw_message)
                if len(raw_message) <= 16384
                else f"Oversized log message withheld ({len(raw_message)} characters)"
            )
            error = (
                "".join(traceback.format_exception(*record.exc_info)) if record.exc_info else None
            )
            if error:
                error = (
                    scrub_text(error)
                    if len(error) <= 16384
                    else "Oversized exception detail withheld"
                )
            value = {
                "@timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
                "log.level": record.levelname.lower(),
                "log.logger": record.name,
                "message": message,
            }
            if error:
                value["error.stack_trace"] = error
            if hasattr(record, "request_id"):
                value["request_id"] = record.request_id
            return dumps(value)
        except Exception:
            return dumps(
                {
                    "log.level": record.levelname.lower(),
                    "message": "Log redaction unavailable; original record withheld",
                    "log.logger": record.name,
                }
            )


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(RedactingJSONFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
