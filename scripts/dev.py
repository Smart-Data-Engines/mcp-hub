"""Bring up an isolated local demo without changing host permissions or groups."""

import base64
import os
import secrets
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

root = Path(__file__).resolve().parents[1]
os.chdir(root)
environment = root / ".env"
if not environment.exists():
    for folder in ("servers", "registry", "demo"):
        (root / ".local" / folder).mkdir(parents=True, exist_ok=True)
    values = {
        "ENVIRONMENT": "development",
        "HUB_PUBLIC_URL": "http://localhost:8000",
        "STORE_PASSWORD": secrets.token_urlsafe(32),
        "CREDENTIALS_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        "HUB_REGISTRATION_SECRET": secrets.token_urlsafe(32),
        "HUB_UPSTREAM_SECRET": secrets.token_urlsafe(32),
        "IDP_PROVIDER": "oidc",
        "IDP_ISSUER": "http://localhost:8100",
        "IDP_BACKCHANNEL_URL": "http://demo-idp:8100",
        "IDP_CLIENT_ID": "mcp-hub-demo",
        "IDP_CLIENT_SECRET": secrets.token_urlsafe(32),
        "REGISTRY_BACKEND": "local",
        "ENABLE_SELF_SERVICE": "true",
        "RUNTIME_IMAGE": "mcp-hub-upstream:local",
        "RUNTIME_HOST_SOURCE_ROOT": str(root / ".local/servers"),
        "REGISTRY_HOST_ROOT": str(root / ".local/registry"),
        "HUB_UID": str(os.getuid()),
        "HUB_GID": str(os.getgid()),
        "DOCKER_GID": str(Path("/var/run/docker.sock").stat().st_gid),
        "CATALOG_REFRESH_INTERVAL": "5",
        "REGISTRY_RECONCILE_INTERVAL": "3",
        "HEARTBEAT_INTERVAL": "10",
    }
    descriptor = os.open(environment, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write("# Generated local demonstration configuration; never commit.\n")
        stream.writelines(f"{key}={value}\n" for key, value in values.items())
elif (
    "ENVIRONMENT=development" not in environment.read_text()
    or "IDP_ISSUER=http://localhost:8100" not in environment.read_text()
):
    raise SystemExit(
        "make dev requires the generated local demo configuration. Preserve your existing .env and use the deployment guide for company configurations."
    )

docker = (
    ["docker"] if os.access("/var/run/docker.sock", os.R_OK | os.W_OK) else ["sudo", "-n", "docker"]
)
compose = [*docker, "compose", "-f", "compose.yaml", "-f", "compose.demo.yaml"]
for command in (
    [*compose, "build", "hub"],
    [*compose, "--profile", "build", "build", "upstream-image"],
    [*compose, "up", "-d"],
):
    subprocess.run(command, check=True)
for _ in range(90):
    try:
        urllib.request.urlopen("http://localhost:8000/ready", timeout=2).close()
        break
    except (urllib.error.URLError, TimeoutError, ConnectionError):
        time.sleep(1)
else:
    raise SystemExit("Hub did not become ready. Inspect docker compose logs hub.")
subprocess.run(
    [*compose, "exec", "-T", "hub", "mcp-hub", "bootstrap-admin", "admin", "admin@example.test"],
    check=True,
)
subprocess.run([*compose, "exec", "-T", "hub", "mcp-hub", "seed-demo"], check=True)
print("MCP Hub is ready at http://localhost:8000/admin/ — choose Admin in the local test provider.")
