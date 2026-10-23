import io
import json
import logging

import httpx
import pytest
from cryptography.fernet import Fernet

from mcp_hub.models import HubError
from mcp_hub.security import Cipher, RedactingJSONFormatter, category, scrub, scrub_text
from mcp_hub.upstream import RequireHubSecret
from mcp_hub.upstreams import LimitedTransport, ResponseLimitError


def test_connection_string_preserves_host_and_username_but_not_password():
    assert (
        scrub_text("postgresql://reader:private-value@database:5432/app")
        == "postgresql://reader:[REDACTED]@database:5432/app"
    )


def test_key_aware_redaction_and_placeholders_and_serialized_json():
    value = {
        "password": "unstructured",
        "query": "select 1",
        "token": None,
        "api_key": "example",
        "content": [{"text": '{"secret":"hello","visible":"world"}'}],
    }
    result = scrub(value)
    assert result["password"] == "[REDACTED]"
    assert (
        result["query"] == "select 1" and result["token"] is None and result["api_key"] == "example"
    )
    assert "hello" not in result["content"][0]["text"]


def test_structured_logger_redacts_exception_and_never_drops_a_record():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingJSONFormatter())
    logger = logging.getLogger("test.redaction")
    logger.handlers, logger.propagate = [handler], False
    try:
        raise ValueError("postgresql://user:s3cr3t@database/app")
    except ValueError:
        logger.exception("password=%s", "another-secret")
    text = stream.getvalue()
    assert "s3cr3t" not in text and "another-secret" not in text
    assert json.loads(text)["error.stack_trace"]


def test_encryption_key_rotation_and_failed_decryption_are_explicit():
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    encrypted = Cipher(old).encrypt({"password": "private"})
    rotated = Cipher(new + "," + old).rotate(encrypted)
    assert Cipher(new).decrypt(rotated) == {"password": "private"}
    with pytest.raises(HubError, match="cannot be decrypted"):
        Cipher(new).decrypt(encrypted)


def test_credentials_written_before_the_crypto_upgrade_remain_readable_and_rotatable():
    # Generated with cryptography 48.0.1 using a public, synthetic test key.
    key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
    encrypted = (
        "gAAAAABq1SNP7n8rw78HVdsZSjf8QurVzMujpXFnQLxoDOWvFzn6lf_560NdAPKHuBqhSpV9tDcx"
        "IVGN2DYkpoi0nKZCd1gLneUQ4KLiBzWgc_2dhtgAM8kyMtvWuKBoXuXlgn-RRz9Mae9oJaTkDQujIdCvKeJyAw=="
    )
    expected = {"API_TOKEN": "legacy-test-value", "REGION": "eu-test-1"}
    assert Cipher(key).decrypt(encrypted) == expected
    new = Fernet.generate_key().decode()
    rotated = Cipher(new + "," + key).rotate(encrypted)
    assert Cipher(new).decrypt(rotated) == expected


def test_category_uses_explicit_annotations_and_conservative_mcp_defaults():
    assert category({"name": "list_merge_requests"}) == ("destructive", False)
    assert category({"name": "list_deletions"}) == ("destructive", False)
    assert category({"name": "deleteRecord"}) == ("destructive", False)
    assert category({"name": "list_deletions", "annotations": {"readOnlyHint": True}}) == (
        "read",
        True,
    )
    assert category({"name": "lookup", "annotations": {"readOnlyHint": False}}) == (
        "destructive",
        True,
    )


def test_upstream_secret_is_mandatory():
    with pytest.raises(ValueError):
        RequireHubSecret(object(), "")


@pytest.mark.parametrize("prefix", ["ntn_", "secret_"])
def test_source_system_tokens_are_redacted_from_unstructured_messages(prefix):
    token = prefix + "A" * 40
    assert scrub_text("Request failed for " + token) == "Request failed for [REDACTED]"


async def test_transport_caps_wire_bytes_before_parsing_and_rejects_compression():
    for headers, payload in (
        ({}, b"x" * 101),
        ({"content-length": "1000"}, b"x"),
        ({"content-encoding": "gzip"}, b"small"),
    ):
        transport = LimitedTransport(100)
        await transport.inner.aclose()
        transport.inner = httpx.MockTransport(
            lambda request, headers=headers, payload=payload: httpx.Response(
                200, headers=headers, stream=httpx.ByteStream(payload)
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(ResponseLimitError):
                await client.get("http://upstream.test/mcp")
