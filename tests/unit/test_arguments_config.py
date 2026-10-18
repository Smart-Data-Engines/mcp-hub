import time

import pytest
from cryptography.fernet import Fernet

from mcp_hub.arguments import validate_arguments, validate_json
from mcp_hub.config import Settings
from mcp_hub.models import HubError


def test_untrusted_schema_cannot_retrieve_remote_refs_or_run_regex():
    schema = {
        "properties": {
            "query": {
                "type": "string",
                "$ref": "http://127.0.0.1:6379/private",
                "pattern": "(a+)+$",
            }
        },
        "required": ["query"],
    }
    started = time.monotonic()
    validate_arguments(schema, {"query": "a" * 100_000 + "!"})
    assert time.monotonic() - started < 0.1


@pytest.mark.parametrize("arguments", [{}, {"unknown": "x"}, {"query": 123}, {"query": True}])
def test_bounded_shape_checks_reject_invalid_arguments(arguments):
    with pytest.raises(HubError):
        validate_arguments(
            {"properties": {"query": {"type": "string"}}, "required": ["query"]}, arguments
        )


def test_invalid_numerical_environment_uses_defaults_and_warns(monkeypatch, caplog):
    for key, value in {
        "STORE_URL": "redis://:test@localhost:6379",
        "CREDENTIALS_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "ENVIRONMENT": "development",
        "ACCESS_TOKEN_TTL": "typo",
        "REFRESH_TOKEN_TTL": "-1",
        "HEARTBEAT_INTERVAL": "0",
        "HUB_PORT": "99999",
        "MAX_RESPONSE_CHARS": "0",
    }.items():
        monkeypatch.setenv(key, value)
    settings = Settings.from_env(dotenv=False)
    assert settings.access_token_ttl == 2_592_000
    assert settings.refresh_token_ttl == 7_776_000
    assert settings.heartbeat_interval == 60
    assert settings.hub_port == 8000
    assert settings.max_response_chars == 0
    assert "using default" in caplog.text


def test_json_depth_encoding_and_nonfinite_values_are_rejected_before_processing():
    nested = {}
    for _ in range(70):
        nested = {"child": nested}
    for value in (nested, {"number": float("nan")}, {"number": float("inf")}, {"text": "\ud800"}):
        with pytest.raises(HubError):
            validate_json(value)
