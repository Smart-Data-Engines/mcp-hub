"""Real certificate stores and bounded logs; no external provider credentials."""

import logging
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from mcp_hub.models import ServerDefinition
from mcp_hub.security import RedactingJSONFormatter
from mcp_hub.tls import trust


def certificate(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def test_explicit_ca_extends_curated_trust_without_ambient_roots(tmp_path, monkeypatch):
    ambient, approved = certificate("synthetic-ambient"), certificate("synthetic-approved")
    ambient_path, approved_path = tmp_path / "ambient.pem", tmp_path / "approved.pem"
    ambient_path.write_bytes(ambient.public_bytes(serialization.Encoding.PEM))
    approved_path.write_bytes(approved.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("SSL_CERT_FILE", str(ambient_path))
    context = trust(str(approved_path))
    roots = context.get_ca_certs(binary_form=True)
    assert approved.public_bytes(serialization.Encoding.DER) in roots
    assert ambient.public_bytes(serialization.Encoding.DER) not in roots
    assert context.check_hostname


def test_oversized_library_log_is_withheld_without_partial_secret_disclosure():
    value = "synthetic-private-credential" + "x" * 50000
    record = logging.LogRecord(
        "mcp.server", logging.WARNING, "test", 1, "Untrusted: %s", (value,), None
    )
    result = RedactingJSONFormatter().format(record)
    assert len(result.encode()) < 1024
    assert "synthetic-private-credential" not in result and "withheld" in result


@pytest.mark.parametrize("field", ["call_timeout", "read_timeout"])
def test_server_time_budgets_cannot_be_nonfinite_strings(field):
    with pytest.raises(ValidationError):
        ServerDefinition(name="demo", owner="owner", **{field: "Infinity"})


def test_revocation_index_cannot_expire_before_access_tokens(settings):
    settings.access_token_ttl = settings.refresh_token_ttl + 1
    with pytest.raises(ValueError, match="revocation"):
        settings.validate()


@pytest.mark.parametrize("environment", ["prod", "Production", "unknown"])
def test_misspelled_environment_cannot_skip_production_checks(settings, environment):
    settings.environment = environment
    with pytest.raises(ValueError, match="ENVIRONMENT"):
        settings.validate()


def test_worker_installer_uses_the_maintained_ca_bundle(monkeypatch):
    import certifi

    from mcp_hub import runner

    calls = []
    monkeypatch.delenv("PIP_CERT", raising=False)
    monkeypatch.setattr(runner.subprocess, "run", lambda args, **kwargs: calls.append(args))
    monkeypatch.setattr(runner.os, "execv", lambda *args: None)
    runner.main()
    install = calls[1]
    assert install[install.index("--cert") + 1] == certifi.where()
    assert "--use-deprecated=legacy-certs" in install
