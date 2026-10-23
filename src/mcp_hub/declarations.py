"""Bounded plain YAML for declarations interpreted by the privileged controller."""

from typing import Any

import yaml

from .models import HubError


class DeclarationLoader(yaml.SafeLoader):
    def __init__(self, document: str):
        super().__init__(document)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent, index):
        self._depth += 1
        self._nodes += 1
        try:
            if self._depth > 16 or self._nodes > 512 or self.check_event(yaml.AliasEvent):
                raise HubError("YAML declarations exceed limits or contain aliases", 422)
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def declaration(document: str) -> dict[str, Any]:
    if len(document.encode()) > 65536:
        raise HubError("YAML declarations must not exceed 64 KiB", 422)
    loader = DeclarationLoader(document)
    try:
        value = loader.get_single_data()
    except (yaml.YAMLError, RecursionError) as exc:
        raise HubError("Invalid YAML declaration", 422) from exc
    finally:
        loader.dispose()
    if value is None:
        return {}
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise HubError("YAML declarations must be mappings with string keys", 422)
    return value
