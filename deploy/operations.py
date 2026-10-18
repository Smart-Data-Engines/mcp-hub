"""Root operator tasks. Configuration and paths are trusted operator input.

Install with the adjacent systemd units; secrets belong in root-owned JSON and
password files, never in this source or command-line arguments. All subprocesses
use argument lists and bounded timeouts; captured errors never print secrets.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import os
import re
import signal
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path("/srv/mcp-hub/shared/operations")
CONFIG = Path("/etc/mcp-hub/operations.json")


def run(argv: list[str], *, env=None, timeout=120, output=None) -> bytes:
    result = subprocess.run(
        argv,
        env=env,
        stdout=output or subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        # Provider errors can contain credentials. Preserve bounded diagnostics
        # only in the protected operator directory, never in stdout/journald.
        if os.geteuid() == 0:
            with contextlib.suppress(OSError):
                folder = ROOT / "diagnostics"
                folder.mkdir(mode=0o700, exist_ok=True)
                write(folder / (uuid.uuid4().hex + ".log"), result.stderr[-65536:])
        raise RuntimeError(f"{Path(argv[0]).name} failed (exit {result.returncode})")
    return result.stdout or b""


def write(path: Path, data: bytes, mode=0o600) -> None:
    fd, name = tempfile.mkstemp(prefix="." + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def without_encryption_key(data: str) -> str:
    return (
        "\n".join(
            line
            for line in data.splitlines()
            if not re.match(r"\s*(?:export\s+)?CREDENTIALS_ENCRYPTION_KEY\s*=", line)
        )
        + "\n"
    )


def is_offsite(repository: str) -> bool:
    # A directory on another partition is still lost with the same machine.
    if repository.startswith(("b2:", "gs:", "azure:")):
        return True
    if not repository.startswith(("s3:", "sftp:", "rest:https://")):
        return False
    address = repository.split(":", 1)[1]
    target = urlsplit(address if "://" in address or address.startswith("//") else "//" + address)
    host = target.hostname
    return bool(
        host
        and host not in {"localhost", "0.0.0.0", "::", "::1", socket.gethostname()}
        and not host.startswith("127.")
    )


class Operations:
    def __init__(self, config: dict, root: Path = ROOT):
        self.config, self.root = config, root
        self.hub = config.get("hub_container", "mcp-hub")
        self.audit = config.get("audit_container", "mcp-hub-audit")
        self.environment = {**os.environ, **config["restic_environment"]}
        self.environment.pop("RESTIC_PASSWORD", None)
        if not self.environment.get("RESTIC_PASSWORD_FILE"):
            raise ValueError("A protected RESTIC_PASSWORD_FILE is required")

    def restic(self, *args: str, output=None) -> bytes:
        return run(["restic", *args], env=self.environment, timeout=1800, output=output)

    def audit_request(self, method: str, path: str, data=None, *, timeout=120) -> dict:
        argv = [
            "docker",
            "exec",
            self.audit,
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            str(timeout),
            "-X",
            method,
            "http://127.0.0.1:9200" + path,
        ]
        if data is not None:
            argv += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(data)]
        return json.loads(run(argv, timeout=timeout + 10))

    def status(self, task: str, **values) -> None:
        # Keep paths independent of command-line strings, including error paths.
        match task:
            case "backup":
                path = self.root / "backup.json"
            case "drill":
                path = self.root / "drill.json"
            case "check":
                path = self.root / "check.json"
            case _:
                raise ValueError("Unknown operator task")
        existing = json.loads(path.read_text()) if path.exists() else {}
        write(path, json.dumps({**existing, **values}, sort_keys=True).encode())

    def backup(self) -> None:
        stage = self.root / "backup-staging"
        stage.mkdir(mode=0o700, exist_ok=True)
        temporary = "/tmp/mcp-hub-backup-" + uuid.uuid4().hex + ".json"
        try:
            run(["docker", "exec", self.hub, "mcp-hub", "backup", temporary])
            (stage / "redis-state.json").unlink(missing_ok=True)
            run(["docker", "cp", self.hub + ":" + temporary, str(stage / "redis-state.json")])
            os.chown(stage / "redis-state.json", 0, 0)
            (stage / "redis-state.json").chmod(0o600)
        finally:
            run(
                [
                    "docker",
                    "exec",
                    self.hub,
                    "python",
                    "-c",
                    "import pathlib,sys; pathlib.Path(sys.argv[1]).unlink(missing_ok=True)",
                    temporary,
                ]
            )
        snapshot = json.loads((stage / "redis-state.json").read_text())
        assert snapshot["format"] == "mcp-hub-redis-dump-v1"
        # The decryption key is recovered from a separate, owner-held package.
        write(
            stage / "hub.env.without-encryption-key",
            without_encryption_key(Path(self.config["hub_env"]).read_text()).encode(),
        )
        current = Path(self.config["current_release"]).resolve()
        manifest = json.loads((current / "manifest.json").read_text())
        write(stage / "release-manifest.json", (current / "manifest.json").read_bytes())
        images = {tag: value["id"] for tag, value in manifest["images"].items()}
        marker = stage / "image-ids.json"
        if (
            not (stage / "images.tar").exists()
            or not marker.exists()
            or json.loads(marker.read_text()) != images
        ):
            for tag in images:
                info = json.loads(run(["docker", "image", "inspect", tag]))[0]
                # Preserve only the two reviewed generic deployment images.
                assert info["Config"]["Cmd"] in (
                    ["mcp-hub", "serve"],
                    ["python", "-m", "mcp_hub.runner"],
                )
            temporary_image = stage / "images.tar.part"
            try:
                with temporary_image.open("wb") as stream:
                    run(["docker", "image", "save", *images], timeout=300, output=stream)
                os.replace(temporary_image, stage / "images.tar")
                write(marker, json.dumps(images, sort_keys=True).encode())
            finally:
                temporary_image.unlink(missing_ok=True)
        name = "backup-" + time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
        result = self.audit_request(
            "PUT",
            "/_snapshot/hub-backups/" + name + "?wait_for_completion=true",
            {"indices": "hub-audit-*", "include_global_state": False},
        )
        assert result["snapshot"]["state"] == "SUCCESS"
        write(stage / "audit-snapshot.json", json.dumps({"name": name, "result": result}).encode())
        self.restic(
            "backup",
            "--json",
            "--host",
            "mcp-hub",
            "--tag",
            "mcp-hub",
            str(stage),
            self.config["audit_snapshot_dir"],
        )
        # Prune through OpenSearch's API, never unlink its repository files.
        snapshots = self.audit_request("GET", "/_snapshot/hub-backups/_all")["snapshots"]
        for item in snapshots:
            if (
                item["snapshot"].startswith("backup-")
                and item["start_time_in_millis"] < (time.time() - 7 * 86400) * 1000
            ):
                self.audit_request("DELETE", "/_snapshot/hub-backups/" + item["snapshot"])
        self.status(
            "backup",
            last_success=time.time(),
            last_attempt_ok=True,
            offsite=is_offsite(self.environment["RESTIC_REPOSITORY"]),
            keys=len(snapshot["entries"]),
        )

    def drill(self) -> None:
        snapshots = json.loads(
            self.restic("snapshots", "--json", "--host", "mcp-hub", "--tag", "mcp-hub")
        )
        latest = max(snapshots, key=lambda item: item["time"])
        assert str(self.root / "backup-staging") in latest["paths"]
        name = "mcp-hub-recovery-" + uuid.uuid4().hex[:12]
        network, store = name, name + "-redis"
        checker = name + "-check"
        with tempfile.TemporaryDirectory(prefix="recovery-", dir=self.root) as temporary:
            folder = Path(temporary)
            with (folder / "redis-state.json").open("wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                self.restic(
                    "dump",
                    latest["id"],
                    str(self.root / "backup-staging/redis-state.json"),
                    output=stream,
                )
            run(["docker", "network", "create", "--internal", network])
            try:
                run(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        store,
                        "--network",
                        network,
                        "--network-alias",
                        "restore-store",
                        "--read-only",
                        "--cap-drop=ALL",
                        "--security-opt=no-new-privileges:true",
                        "--tmpfs",
                        "/data:mode=1777",
                        "--user",
                        "999:999",
                        "--memory",
                        "256m",
                        self.config["redis_image"],
                        "redis-server",
                        "--appendonly",
                        "no",
                        "--save",
                        "",
                    ]
                )
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    try:
                        if run(["docker", "exec", store, "redis-cli", "ping"]).strip() == b"PONG":
                            break
                    except RuntimeError:
                        pass
                    time.sleep(0.2)
                else:
                    raise RuntimeError("Disposable recovery Redis did not become ready")
                # The checker receives only a snapshot, a key file and an isolated
                # Redis address. It has no socket, registry, source or host ports.
                image = (
                    run(["docker", "inspect", "--format", "{{.Config.Image}}", self.hub])
                    .decode()
                    .strip()
                )
                output = run(
                    [
                        "docker",
                        "run",
                        "--name",
                        checker,
                        "--network",
                        network,
                        "--user",
                        "0:0",
                        "--read-only",
                        "--cap-drop=ALL",
                        "--security-opt=no-new-privileges:true",
                        "--memory",
                        "256m",
                        "--pids-limit",
                        "64",
                        "--tmpfs",
                        "/tmp:mode=1777",
                        "-v",
                        str(folder) + ":/recovery:ro",
                        "-v",
                        self.config["hub_env"] + ":/run/recovery.env:ro",
                        "-v",
                        self.config["restore_check"] + ":/check.py:ro",
                        "--entrypoint",
                        "python",
                        image,
                        "/check.py",
                    ]
                )
                proof = json.loads(output)
                assert proof["production_connections"] == 0
                self.status(
                    "drill",
                    last_success=time.time(),
                    last_attempt_ok=True,
                    snapshot=latest["id"],
                    **proof,
                )
            finally:
                for container in (checker, store):
                    with contextlib.suppress(Exception):
                        run(["docker", "rm", "-f", container])
                run(["docker", "network", "rm", network])

    def check_repository(self) -> None:
        self.restic("check", "--read-data")
        self.restic(
            "forget",
            "--host",
            "mcp-hub",
            "--tag",
            "mcp-hub",
            "--group-by",
            "host,paths,tags",
            "--keep-hourly",
            "24",
            "--keep-daily",
            "14",
            "--keep-weekly",
            "8",
            "--keep-monthly",
            "6",
            "--prune",
        )
        self.status("check", last_success=time.time(), last_attempt_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task", choices=("backup", "drill", "check"))
    task = parser.parse_args().task
    if os.geteuid() != 0:
        raise SystemExit("Root operator execution required")
    metadata = CONFIG.stat()
    if (
        metadata.st_uid != 0
        or metadata.st_mode & 0o077
        or CONFIG.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise SystemExit("Configuration must be a regular root-owned mode 0600 file")
    config = json.loads(CONFIG.read_text())
    os.umask(0o077)

    def interrupted(signum, frame):
        raise InterruptedError("Operator task interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    operations = Operations(config)
    method = operations.check_repository if task == "check" else getattr(operations, task)
    # Serialize maintenance with deployments and key rotation.
    with open(config["deployment_lock"], "a") as lock:
        try:
            deadline = time.monotonic() + 45
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Maintenance lock remains busy") from None
                    time.sleep(0.5)
            method()
        except Exception as exc:
            operations.status(
                task, last_attempt_ok=False, last_failure=time.time(), error_type=type(exc).__name__
            )
            raise SystemExit(
                f"{task} failed: {type(exc).__name__}; inspect protected operator diagnostics"
            ) from None


if __name__ == "__main__":
    main()
