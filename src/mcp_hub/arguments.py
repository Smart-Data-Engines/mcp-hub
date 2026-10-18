"""Bounded gateway shape checks, without evaluating tool-supplied code or URLs.

Full JSON Schema validation belongs to the isolated upstream SDK. Executing remote
$ref retrieval or arbitrary regular expressions in the privileged hub would let
an untrusted tool definition reach the hub's network or block its event loop.
"""

import math
from typing import Any

from .models import HubError


def validate_json(value: Any) -> None:
    pending = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if depth > 64 or visited > 100_000:
            raise HubError(
                "JSON exceeds the nesting or element limit", 413, code="invalid_arguments"
            )
        if isinstance(item, float) and not math.isfinite(item):
            raise HubError("JSON numbers must be finite", 422, code="invalid_arguments")
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise HubError(
                    "JSON strings must be valid UTF-8", 400, code="invalid_arguments"
                ) from exc
        elif isinstance(item, dict):
            pending.extend((child, depth + 1) for pair in item.items() for child in pair)
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def validate_arguments(schema: dict[str, Any], arguments: dict[str, Any]) -> None:
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise HubError("Upstream supplied an invalid argument schema", 502, code="invalid_schema")
    if any(not isinstance(key, str) or key not in arguments for key in required):
        raise HubError(
            "Required tool arguments are missing; inspect tools/list", 422, code="invalid_arguments"
        )
    if any(key not in properties for key in arguments):
        raise HubError("Unknown tool arguments; inspect tools/list", 422, code="invalid_arguments")
    for key, value in arguments.items():
        specification = properties.get(key)
        if not isinstance(specification, dict):
            continue
        declared = specification.get("type")
        kinds = [declared] if isinstance(declared, str) else declared
        if not isinstance(kinds, list) or not kinds:
            continue
        valid = {
            "null": value is None,
            "string": isinstance(value, str),
            "boolean": isinstance(value, bool),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": (isinstance(value, int) and not isinstance(value, bool))
            or (isinstance(value, float) and math.isfinite(value)),
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
        }
        if not any(valid.get(kind, False) for kind in kinds if isinstance(kind, str)):
            raise HubError(
                "Tool argument type does not match its schema; inspect tools/list",
                422,
                code="invalid_arguments",
            )
