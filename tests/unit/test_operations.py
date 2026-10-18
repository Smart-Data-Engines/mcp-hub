import importlib.util
import json
import ssl
import subprocess
from pathlib import Path

import pytest

_source = Path(__file__).resolve().parents[2] / "deploy/operations.py"
_spec = importlib.util.spec_from_file_location("hub_operations", _source)
assert _spec and _spec.loader
ops = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ops)


@pytest.mark.parametrize(
    "repository",
    [
        "/srv/backup",
        "./backup",
        "s3:http://127.0.0.1/bucket",
        "sftp:localhost:/backup",
        "rest:https://[::1]/backup",
    ],
)
def test_same_host_repositories_do_not_clear_the_offsite_warning(repository):
    assert not ops.is_offsite(repository)


@pytest.mark.parametrize(
    "repository",
    ["s3:https://storage.example.test/bucket/hub", "sftp:backup@storage.example.test:/backups/hub"],
)
def test_remote_storage_backends_are_recognized(repository):
    assert ops.is_offsite(repository)


@pytest.mark.parametrize(
    "assignment", ["CREDENTIALS_ENCRYPTION_KEY=", " export   CREDENTIALS_ENCRYPTION_KEY ="]
)
def test_data_backup_removes_current_and_rotating_keys_but_keeps_other_config(assignment):
    source = "# configuration\n" + assignment + "current-key,old-key\nIDP_CLIENT_ID=client\n"
    result = ops.without_encryption_key(source)
    assert "current-key" not in result and "old-key" not in result
    assert "IDP_CLIENT_ID=client\n" in result


def test_status_replacement_is_private_and_failed_write_keeps_the_previous_file(
    tmp_path, monkeypatch
):
    destination = tmp_path / "status.json"
    ops.write(destination, b'{"last_success":1}')
    assert destination.stat().st_mode & 0o777 == 0o600

    def fail(*args):
        raise OSError("simulated full filesystem")

    monkeypatch.setattr(ops.os, "replace", fail)
    with pytest.raises(OSError):
        ops.write(destination, b'{"last_success":2}')
    assert json.loads(destination.read_bytes()) == {"last_success": 1}
    assert list(tmp_path.iterdir()) == [destination]


def test_command_failures_do_not_copy_sensitive_diagnostics_into_logs(monkeypatch):
    monkeypatch.setattr(
        ops.subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a[0], 3, b"", b"sensitive provider diagnostics"
        ),
    )
    with pytest.raises(RuntimeError, match="restic failed") as exc:
        ops.run(["restic", "backup"])
    assert "sensitive" not in str(exc.value)


def test_status_paths_reject_traversal_before_any_filesystem_access(tmp_path):
    operation = ops.Operations(
        {"restic_environment": {"RESTIC_PASSWORD_FILE": "/secure/key"}}, tmp_path
    )
    with pytest.raises(ValueError, match="Unknown operator task"):
        operation.status("../../escape", last_success=1)
    assert not list(tmp_path.iterdir())


def test_probe_tls_rejects_legacy_protocols_and_keeps_certificate_checks():
    context = ops.tls_context()
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_failed_backup_does_not_rewrite_its_last_success(tmp_path):
    operation = ops.Operations(
        {"restic_environment": {"RESTIC_PASSWORD_FILE": "/secure/key"}}, tmp_path
    )
    operation.status("backup", last_success=100, last_attempt_ok=True)
    operation.status("backup", last_failure=200, last_attempt_ok=False)
    assert json.loads((tmp_path / "backup.json").read_text()) == {
        "last_success": 100,
        "last_failure": 200,
        "last_attempt_ok": False,
    }
