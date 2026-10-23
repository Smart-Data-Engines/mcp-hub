"""Docker lifecycle. The untrusted server receives no hub-wide secret or state access."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import logging
import math
import re
import secrets
import shutil
import socket
from collections.abc import Callable
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import docker
import yaml
from docker.errors import NotFound
from docker.models.containers import Container
from packaging.requirements import Requirement
from packaging.version import Version

from .config import Settings
from .credentials import Credentials
from .declarations import declaration
from .models import HubError, ServerDefinition
from .registry import Registry, validate_files, validate_path
from .security import cap_text, scrub_text, secret_values
from .store import Store, digest
from .upstream import scaffold
from .upstreams import Upstreams

log = logging.getLogger(__name__)
LABEL = "io.smartdataengines.mcp-hub"


def validate_worker_sdk(document: str) -> None:
    """Bound v1 deployments and require reproducible exact pins for SDK 2 workers."""
    pinned = False
    for line in document.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        try:
            requirement = Requirement(stripped)
        except ValueError as exc:
            raise HubError("Invalid requirements.txt", 422) from exc
        if requirement.name.lower() != "mcp":
            continue
        bounded_v1 = (
            any(
                (spec.operator in {"==", "~="} and spec.version.split(".")[0] == "1")
                or (
                    spec.operator == "<"
                    and Version(spec.version).major in {1, 2}
                    and Version(spec.version) <= Version("2.0")
                )
                or (spec.operator == "<=" and Version(spec.version).major == 1)
                for spec in requirement.specifier
            )
            and not requirement.specifier.contains(Version("2.0"))
            and not requirement.specifier.contains(Version("3.0"))
        )
        exact_v2 = any(
            spec.operator == "=="
            and "*" not in spec.version
            and Version(spec.version).major == 2
            and Version(spec.version) >= Version("2.3")
            and requirement.specifier.contains(Version(spec.version), prereleases=False)
            for spec in requirement.specifier
        )
        pinned = bounded_v1 or exact_v2
    if not pinned:
        raise HubError(
            "requirements.txt must bound MCP v1 (mcp>=1.30,<2) or pin an exact supported SDK 2 version (mcp==2.3.0)",
            422,
        )


def resource_limits(document: str) -> tuple[int, float]:
    try:
        data = declaration(document)
        if not isinstance(data, dict):
            raise ValueError
        memory = data.get("memory", "512m")
        if not isinstance(memory, str) or not (
            match := re.fullmatch(r"([0-9]{1,10})([mg])", memory.lower())
        ):
            raise ValueError
        memory_mb = int(match[1]) * (1024 if match[2] == "g" else 1)
        if isinstance(data.get("cpus"), bool):
            raise ValueError
        cpus = float(data.get("cpus", "1.0"))
        if not math.isfinite(cpus):
            raise ValueError
        return max(64, min(2048, memory_mb)), max(0.1, min(2.0, cpus))
    except (ValueError, TypeError, OverflowError, yaml.YAMLError) as exc:
        raise HubError(
            "docker.yaml requires memory in m/g units and a finite CPU value", 422
        ) from exc


def container_name(name: str) -> str:
    return "mcp-hub-srv-" + digest(name)[:16]


def registration_secret(master: str, name: str) -> str:
    return hmac.new(master.encode(), ("registration:" + name).encode(), hashlib.sha256).hexdigest()


class Runtime:
    def __init__(
        self,
        store: Store,
        settings: Settings,
        registry: Registry,
        credentials: Credentials,
        upstreams: Upstreams,
    ):
        self.store, self.settings, self.registry = store, settings, registry
        self.credentials, self.upstreams = credentials, upstreams
        self.verified = False
        self.client: docker.DockerClient | None = None

    async def verify(self) -> None:
        if not self.settings.enable_self_service:
            return

        def check() -> None:
            if not urlsplit(self.settings.store_url).password:
                raise HubError("Self-service requires a password-protected Redis server", 503)
            self.client = docker.from_env(timeout=10)
            self.client.ping()
            hub = self.client.containers.get(self.settings.runtime_hub_container)
            networks = hub.attrs["NetworkSettings"]["Networks"]
            if (
                self.settings.network_state not in networks
                or self.settings.network_ingress not in networks
            ):
                raise HubError("Hub must have separate state and ingress networks", 503)
            ingress_ip = networks[self.settings.network_ingress]["IPAddress"]
            if socket.gethostbyname(self.settings.hub_bind_host) != ingress_ip:
                raise HubError(
                    "Control listener must bind only to the ingress network address", 503
                )
            if not self.settings.runtime_host_source_root:
                raise HubError(
                    "RUNTIME_HOST_SOURCE_ROOT is required for isolated source mounts", 503
                )
            state = self.client.networks.get(self.settings.network_state)
            state.reload()
            for identifier in state.attrs.get("Containers", {}):
                member = self.client.containers.get(identifier)
                if member.labels.get(LABEL) == "server":
                    raise HubError("An upstream container belongs to the state network", 503)

        await asyncio.to_thread(check)
        self.verified = True

    def _require(self) -> docker.DockerClient:
        if not self.settings.enable_self_service or not self.verified or self.client is None:
            raise HubError(
                "Server runtime is disabled until its isolated Docker topology is configured and verified",
                503,
            )
        return self.client

    async def create(self, definition: ServerDefinition) -> ServerDefinition:
        self._require()
        if definition.name == "hub":
            raise HubError("The name hub is reserved", 409)
        result = await self.store.save_dynamic(
            definition.name,
            definition.model_dump(),
            create=True,
            limit=self.settings.max_servers_per_owner,
        )
        if result == -1:
            raise HubError("Server name is already in use or reserved to its previous owner", 409)
        if result == -2:
            raise HubError("Owner server limit reached", 409)
        try:
            folder = f"{definition.owner}/{definition.name}"
            existing = await self.registry.snapshot(folder)
            if existing.files:
                manifest = declaration(existing.files.get("manifest.yaml", ""))
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("name") != definition.name
                    or manifest.get("owner") != definition.owner
                ):
                    raise HubError(
                        "Existing registry folder has a different name/owner; source was not changed",
                        409,
                    )
                if any(
                    required not in existing.files
                    for required in ("server.py", "requirements.txt", "env.yaml", "docker.yaml")
                ):
                    raise HubError(
                        "Existing registry folder is incomplete; source was not changed", 422
                    )
            else:
                files = scaffold(definition.name, definition.owner)
                files["docker.yaml"] = yaml.safe_dump(
                    {"memory": f"{definition.memory_mb}m", "cpus": str(definition.cpus)}
                )
                await self.registry.commit(
                    folder, files, f"Create MCP server {definition.name}", existing.commit
                )
        except BaseException:
            await self.store.delete_dynamic(definition.name)
            raise
        return definition

    async def definition(self, name: str) -> ServerDefinition:
        value = (await self.store.dynamic()).get(name)
        if value is None:
            raise HubError("Server not found", 404)
        return ServerDefinition.model_validate(value)

    async def _lease(self, name: str) -> str:
        token = secrets.token_urlsafe(24)
        if not await self.store.put("runtime:lock:" + name, token, ttl=600, nx=True):
            raise HubError("Another lifecycle operation is in progress", 409)
        return token

    async def save(self, definition: ServerDefinition, *, fields: set[str] | None = None) -> None:
        selected = (
            fields if fields is not None else {"status", "code_version", "error", "user_env_fields"}
        )
        await self.store.patch_dynamic(
            definition.name,
            {key: value for key, value in definition.model_dump().items() if key in selected},
        )
        self.upstreams.wake.set()

    def _network_name(self, name: str) -> str:
        return self.settings.network_upstream_prefix + digest(name)[:16]

    def _network(self, name: str):
        client = self._require()
        network_name = self._network_name(name)
        try:
            network = client.networks.get(network_name)
            if (
                network.attrs.get("Labels", {}).get(LABEL) != "network"
                or network.attrs.get("Labels", {}).get("hub.server") != name
            ):
                raise HubError("Runtime network name belongs to an unmanaged network", 409)
        except NotFound:
            network = client.networks.create(
                network_name,
                driver="bridge",
                labels={LABEL: "network", "hub.server": name},
                options={"com.docker.network.bridge.gateway_mode_ipv4": "nat"},
            )
        hub = client.containers.get(self.settings.runtime_hub_container)
        hub.reload()
        if network_name not in hub.attrs["NetworkSettings"]["Networks"]:
            network.connect(hub, aliases=["hub-registration"])
        return network

    def _stop(self, name: str) -> None:
        client = self._require()
        try:
            container = client.containers.get(container_name(name))
            if container.labels.get(LABEL) != "server":
                raise HubError("Refusing to stop an unmanaged container", 409)
            container.remove(force=True)
        except NotFound:
            pass
        try:
            network = client.networks.get(self._network_name(name))
            if network.attrs.get("Labels", {}).get(LABEL) != "network":
                raise HubError("Refusing to remove an unmanaged network", 409)
            network.reload()
            own_id = client.containers.get(self.settings.runtime_hub_container).id
            for identifier in network.attrs.get("Containers", {}):
                member = client.containers.get(identifier)
                if identifier != own_id and member.labels.get(LABEL) != "controller":
                    raise HubError(
                        "Owned upstream network contains an unmanaged endpoint; operator review is required",
                        409,
                    )
                with contextlib.suppress(NotFound):
                    network.disconnect(identifier, force=True)
            network.remove()
        except NotFound:
            pass

    async def stop(self, name: str) -> ServerDefinition:
        self._require()
        lease = await self._lease(name)
        try:
            definition = await self.definition(name)
            definition.status = "stopping"
            await self.save(definition)
            await asyncio.to_thread(self._stop, name)
            await self.upstreams.unregister(name)
            definition.status, definition.error = "stopped", ""
            await self.save(definition)
            return definition
        finally:
            await self.store.unlock("runtime:lock:" + name, lease)

    def _materialize(self, name: str, revision: str, files: dict[str, str]) -> Path:
        if not re.fullmatch(r"[a-f0-9]{40}", revision, flags=re.ASCII):
            raise HubError("Registry returned an invalid snapshot identifier", 502)
        root = Path(self.settings.server_source_dir).resolve()
        folder = root / name / revision
        folder.mkdir(parents=True, exist_ok=True)
        for filename, content in files.items():
            validate_path(filename)
            target = folder / filename
            if target.is_symlink() or not target.resolve().is_relative_to(folder.resolve()):
                raise HubError("Unsafe source path", 422)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if target.read_text() != content:
                    raise HubError("An immutable source snapshot was changed on disk", 409)
                continue
            target.write_text(content)
            target.chmod(0o444)
        previous = sorted(
            (
                path
                for path in folder.parent.iterdir()
                if path.is_dir()
                and not path.is_symlink()
                and path.name != revision
                and re.fullmatch(r"[a-f0-9]{40}", path.name)
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for stale in previous[1:]:
            shutil.rmtree(stale)
        return folder

    async def start(self, name: str, *, restart: bool = False) -> ServerDefinition:
        client = self._require()
        lease = await self._lease(name)
        definition = await self.definition(name)
        try:
            if definition.status == "running" and not restart:
                raise HubError("Server is already running; use Restart to pull fresh source", 409)
            await asyncio.to_thread(self._stop, name)
            await self.upstreams.unregister(name)
            definition.status, definition.error = "starting", ""
            await self.save(definition)
            snapshot = await self.registry.snapshot(
                f"{definition.owner}/{name}", definition.pinned_ref
            )
            for required in (
                "server.py",
                "requirements.txt",
                "manifest.yaml",
                "env.yaml",
                "docker.yaml",
            ):
                if required not in snapshot.files:
                    raise HubError("Registry snapshot is missing " + required, 422)
            validate_files(snapshot.files)
            memory_mb, cpus = resource_limits(snapshot.files["docker.yaml"])
            if (memory_mb, cpus) != (definition.memory_mb, definition.cpus):
                raise HubError(
                    "Registry resource limits differ from the administrator-approved settings; ask an administrator to save the limits in the console",
                    422,
                )
            validate_worker_sdk(snapshot.files["requirements.txt"])
            declared = declaration(snapshot.files["env.yaml"])
            if any(
                not isinstance(declared.get(key, []), list)
                or any(not isinstance(field, str) for field in declared.get(key, []))
                for key in ("env", "user_env")
            ):
                raise HubError("env.yaml must declare env and user_env lists", 422)
            values = await self.credentials.global_env(name)
            definition.user_env_fields = declared.get("user_env", [])
            environment = {
                key: value for key, value in values.items() if key in declared.get("env", [])
            }
            await self.store.redis.set(
                self.store.key("mcp:running-env:" + name),
                self.credentials.cipher.encrypt(environment),
            )
            definition.code_version = snapshot.commit
            await self.save(definition)
            await asyncio.to_thread(self._materialize, name, snapshot.commit, snapshot.files)
            source = str(Path(self.settings.runtime_host_source_root) / name / snapshot.commit)
            network = await asyncio.to_thread(self._network, name)
            environment.update(
                {
                    "HUB_URL": f"http://hub-registration:{self.settings.registration_port}",
                    "SERVER_NAME": name,
                    "SERVER_URL": f"http://{container_name(name)}:3000/mcp",
                    "HUB_REGISTRATION_SECRET": registration_secret(
                        self.settings.hub_registration_secret, name
                    ),
                    "HUB_UPSTREAM_SECRET": self.upstreams.secret(name, True),
                    "HUB_CODE_VERSION": snapshot.commit,
                    "HEARTBEAT_INTERVAL": str(self.settings.heartbeat_interval),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONUNBUFFERED": "1",
                }
            )
            launcher = cast(Callable[..., Container], client.containers.run)
            container = await asyncio.to_thread(
                launcher,
                self.settings.runtime_image,
                name=container_name(name),
                detach=True,
                network=network.name,
                environment=environment,
                user="10001:10001",
                volumes={source: {"bind": "/server", "mode": "ro"}},
                working_dir="/server",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                pids_limit=128,
                mem_limit=f"{definition.memory_mb}m",
                nano_cpus=int(definition.cpus * 1_000_000_000),
                tmpfs={"/tmp": "rw,nosuid,nodev,size=536870912,mode=1777"},
                labels={LABEL: "server", "hub.server": name, "hub.code_version": snapshot.commit},
                restart_policy={"Name": "no"},
            )
            for _ in range(120):
                entry = (await self.store.registered()).get(name)
                if entry and entry.get("code_version") == snapshot.commit:
                    definition.status = "running"
                    await self.save(definition)
                    return definition
                await asyncio.to_thread(container.reload)
                if container.status in {"exited", "dead"}:
                    raise HubError(
                        "Server exited during startup. " + await self.logs(name, tail=30), 502
                    )
                await asyncio.sleep(0.5)
            raise HubError("Server did not register within 60 seconds; inspect its logs", 502)
        except HubError as exc:
            if exc.status != 409:
                definition.status, definition.error = "error", cap_text(exc.message, 2000)
                await self.save(definition)
            raise
        except Exception as exc:
            definition.status, definition.error = (
                "error",
                "Runtime start failed: " + type(exc).__name__,
            )
            await self.save(definition)
            raise HubError(definition.error, 502) from exc
        finally:
            await self.store.unlock("runtime:lock:" + name, lease)

    async def logs(self, name: str, tail: int = 100) -> str:
        client = self._require()
        try:
            container = await asyncio.to_thread(client.containers.get, container_name(name))
            raw = await asyncio.to_thread(container.logs, tail=min(1000, max(1, tail)))
        except NotFound:
            return "No container logs yet. Start the server first."
        known = secret_values(await self.credentials.global_env(name, running=True)) + (
            registration_secret(self.settings.hub_registration_secret, name),
            self.upstreams.secret(name, True),
        )
        return cap_text(scrub_text(raw.decode(errors="replace"), known), 65_536)

    def _clear_source_cache(self, name: str) -> None:
        source_cache = Path(self.settings.server_source_dir).resolve() / name
        if source_cache.is_dir() and not source_cache.is_symlink():
            shutil.rmtree(source_cache)

    async def delete(self, name: str) -> None:
        definition = await self.stop(name)
        snapshot = await self.registry.snapshot(f"{definition.owner}/{name}")
        if snapshot.files:
            await self.registry.commit(
                f"{definition.owner}/{name}",
                {filename: None for filename in snapshot.files},
                f"Delete MCP server {name}",
                snapshot.commit,
            )
        await self.store.delete_dynamic(name)
        await asyncio.to_thread(self._clear_source_cache, name)
        await self.store.delete("mcp:env:" + name)
        await self.store.delete("mcp:running-env:" + name)
        await self.upstreams.unregister(name)

    async def reconnect_running(self) -> None:
        if not self.verified:
            return
        for name, data in (await self.store.dynamic()).items():
            if data["status"] == "running":
                try:
                    await self.attach_network(name)
                except Exception as exc:
                    log.warning(
                        "Runtime network recovery failed for %s: %s", name, type(exc).__name__
                    )

    async def attach_network(self, name: str) -> None:
        if self.verified and not await self.store.get("runtime:lock:" + name):
            await asyncio.to_thread(self._network, name)

    async def resume(self) -> None:
        if not self.verified:
            return
        client = self._require()
        for name, data in (await self.store.dynamic()).items():
            if not data.get("autostart") and data.get("status") != "running":
                continue
            try:
                try:
                    container = await asyncio.to_thread(client.containers.get, container_name(name))
                    await asyncio.to_thread(container.reload)
                    if container.status == "running":
                        continue
                except NotFound:
                    pass
                await self.start(name, restart=True)
            except Exception as exc:
                log.warning("Automatic server recovery failed for %s: %s", name, type(exc).__name__)
            await asyncio.sleep(0.25)
