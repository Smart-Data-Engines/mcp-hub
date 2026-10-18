"""Versioned source snapshots and atomic batch commits, independent of runtime."""

from __future__ import annotations

import asyncio
import base64
import os
import shlex
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.parse import quote, urlsplit

import httpx

from .config import Settings
from .models import HubError


def validate_path(path: str) -> str:
    parts = PurePosixPath(path).parts
    if (
        not path
        or len(path) > 255
        or path.startswith("/")
        or "\\" in path
        or len(parts) > 8
        or any(ord(c) < 32 or ord(c) == 127 for c in path)
        or any(part in {"", ".", "..", ".git"} for part in path.split("/"))
    ):
        raise HubError("File path must stay inside the server folder")
    return path


def validate_files(files: Mapping[str, str | None]) -> None:
    if not isinstance(files, dict) or len(files) > 100:
        raise HubError("A commit may contain at most 100 text files")
    total = 0
    for name, value in files.items():
        validate_path(name)
        if value is not None:
            if not isinstance(value, str) or len(value.encode()) > 1_048_576:
                raise HubError("Each source file must be UTF-8 text of at most 1 MiB")
            total += len(value.encode())
    if total > 10_485_760:
        raise HubError("A source snapshot must not exceed 10 MiB")


@dataclass(slots=True)
class Snapshot:
    commit: str
    files: dict[str, str]


def source_location(settings: Settings, folder: str, pinned_ref: str = "") -> dict:
    """Describe a source location without exposing Git authentication or local paths."""
    reference = pinned_ref or settings.registry_branch
    result = {
        "provider": "Local Git",
        "repository": "Workspace Git registry",
        "repository_url": None,
        "folder_url": None,
        "folder": folder,
        "branch": settings.registry_branch,
        "reference": reference,
        "pinned": bool(pinned_ref),
        "editing_enabled": not settings.registry_read_only,
    }
    if settings.registry_backend == "local":
        return result
    remote = (
        "https://github.com/" + settings.registry_repository
        if settings.registry_backend == "github"
        else settings.registry_git_remote
    )
    if "://" not in remote and "@" in remote and ":" in remote:
        host, path = remote.split("@", 1)[1].split(":", 1)
        remote = "ssh://" + host + "/" + path
    try:
        parsed = urlsplit(remote)
        host = parsed.hostname or ""
        path = parsed.path.strip("/").removesuffix(".git")
        if parsed.scheme not in {"https", "http", "ssh", "git"} or not host or not path:
            return {**result, "provider": "Git", "repository": "Configured Git registry"}
        if any(char.isspace() or ord(char) < 32 for char in host) or any(
            char in host for char in "/\\<>\"'"
        ):
            return {**result, "provider": "Git", "repository": "Configured Git registry"}
    except ValueError:
        return {**result, "provider": "Git", "repository": "Configured Git registry"}
    repository_url = "https://" + host + "/" + quote(path, safe="/")
    provider, tree = (
        ("Bitbucket", "/src/")
        if host == "bitbucket.org"
        else ("GitHub", "/tree/")
        if host == "github.com"
        else ("GitLab", "/-/tree/")
        if host == "gitlab.com"
        else ("Git", "")
    )
    return {
        **result,
        "provider": provider,
        "repository": host + "/" + path,
        "repository_url": repository_url,
        "folder_url": (
            repository_url + tree + quote(reference, safe="") + "/" + quote(folder, safe="/")
            if tree
            else repository_url
        ),
    }


class Registry(Protocol):
    async def snapshot(self, folder: str, ref: str = "") -> Snapshot: ...
    async def commit(
        self, folder: str, files: Mapping[str, str | None], message: str, expected: str = ""
    ) -> str: ...


class GitHubRegistry:
    def __init__(self, settings: Settings, client: httpx.AsyncClient):
        self.settings, self.client = settings, client

    async def _api(self, method: str, path: str, **kwargs) -> dict:
        if not self.settings.registry_repository or not self.settings.registry_token:
            raise HubError(
                "Git registry is not configured; set REGISTRY_REPOSITORY and REGISTRY_TOKEN", 503
            )
        if len(self.settings.registry_repository.split("/")) != 2:
            raise HubError("REGISTRY_REPOSITORY must be owner/repository", 503)
        response = await self.client.request(
            method,
            f"https://api.github.com/repos/{self.settings.registry_repository}/{path}",
            headers={
                "Authorization": "Bearer " + self.settings.registry_token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=15,
            **kwargs,
        )
        if response.status_code in {409, 422}:
            raise HubError("Registry changed concurrently; reload the files before committing", 409)
        if response.status_code >= 400:
            raise HubError(
                "Git registry request failed; check repository access and branch configuration", 502
            )
        return response.json()

    async def snapshot(self, folder: str, ref: str = "") -> Snapshot:
        validate_path(folder)
        commit = await self._api(
            "GET", "commits/" + quote(ref or self.settings.registry_branch, safe="")
        )
        tree = await self._api(
            "GET", "git/trees/" + commit["commit"]["tree"]["sha"] + "?recursive=1"
        )
        if tree.get("truncated"):
            raise HubError("Registry tree is too large for a complete snapshot", 502)
        entries = [
            entry
            for entry in tree["tree"]
            if entry["path"].startswith(folder + "/") and entry["type"] != "tree"
        ]
        if len(entries) > 100 or any(
            entry.get("mode") != "100644" and entry.get("mode") != "100755" for entry in entries
        ):
            raise HubError("Server source contains too many files, a symlink or a submodule", 422)
        semaphore = asyncio.Semaphore(8)

        async def blob(entry: dict) -> tuple[str, str]:
            name = validate_path(entry["path"][len(folder) + 1 :])
            if entry.get("size", 0) > 1_048_576:
                raise HubError("Source file exceeds 1 MiB", 422)
            async with semaphore:
                data = await self._api("GET", "git/blobs/" + entry["sha"])
            try:
                return name, base64.b64decode(data["content"]).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as exc:
                raise HubError("Source files must be UTF-8 text", 422) from exc

        files = dict(await asyncio.gather(*(blob(entry) for entry in entries)))
        validate_files(files)
        return Snapshot(commit["sha"], files)

    async def commit(
        self, folder: str, files: Mapping[str, str | None], message: str, expected: str = ""
    ) -> str:
        if self.settings.registry_read_only:
            raise HubError(
                "Registry is read-only. Publish source changes to Git, then restart the server.",
                403,
            )
        validate_path(folder)
        validate_files(files)
        branch = quote(self.settings.registry_branch, safe="")
        reference = await self._api("GET", "git/ref/heads/" + branch)
        parent = reference["object"]["sha"]
        if expected and expected != parent:
            raise HubError("Registry changed; reload before committing", 409)
        commit = await self._api("GET", "git/commits/" + parent)
        entries = []
        for name, content in files.items():
            entries.append(
                {
                    "path": folder + "/" + name,
                    "mode": "100644",
                    "type": "blob",
                    **({"sha": None} if content is None else {"content": content}),
                }
            )
        tree = await self._api(
            "POST", "git/trees", json={"base_tree": commit["tree"]["sha"], "tree": entries}
        )
        created = await self._api(
            "POST",
            "git/commits",
            json={"message": message[:500], "tree": tree["sha"], "parents": [parent]},
        )
        await self._api(
            "PATCH", "git/refs/heads/" + branch, json={"sha": created["sha"], "force": False}
        )
        return created["sha"]


class LocalGitRegistry:
    """Local demo/test registry: a real bare Git repository, never the hub checkout."""

    def __init__(self, path: str, branch: str = "main", *, read_only: bool = False):
        self.path, self.branch = Path(path).resolve(), branch
        self.read_only = read_only
        self._lock = asyncio.Lock()

    def _git(self, *args: str, data: bytes | None = None, env: dict | None = None) -> bytes:
        variables = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "MCP Hub",
            "GIT_AUTHOR_EMAIL": "hub@localhost",
            "GIT_COMMITTER_NAME": "MCP Hub",
            "GIT_COMMITTER_EMAIL": "hub@localhost",
            **(env or {}),
        }
        result = subprocess.run(
            ["git", "--git-dir", str(self.path), *args],
            input=data,
            capture_output=True,
            env=variables,
            timeout=15,
        )
        if result.returncode:
            raise HubError(
                "Local Git operation failed or conflicted; reload the source snapshot", 409
            )
        return result.stdout

    def _initialize(self) -> None:
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "init", "--bare", "--initial-branch=" + self.branch, str(self.path)],
                check=True,
                capture_output=True,
                timeout=15,
            )
            tree = self._git("mktree", data=b"").decode().strip()
            commit = (
                self._git("commit-tree", tree, "-m", "Initialize MCP server registry")
                .decode()
                .strip()
            )
            self._git("update-ref", "refs/heads/" + self.branch, commit, "0" * 40)

    def _snapshot(self, folder: str, ref: str) -> Snapshot:
        self._initialize()
        revision = (
            self._git(
                "rev-parse", "--verify", "--end-of-options", (ref or self.branch) + "^{commit}"
            )
            .decode()
            .strip()
        )
        records = self._git("ls-tree", "-r", "-z", revision, "--", folder).split(b"\0")
        files: dict[str, str] = {}
        for record in records:
            if not record:
                continue
            metadata, path = record.split(b"\t", 1)
            mode, kind, sha = metadata.decode().split()
            if mode not in {"100644", "100755"} or kind != "blob":
                raise HubError("Symlinks and submodules are forbidden in server source", 422)
            name = validate_path(path.decode()[len(folder) + 1 :])
            size = int(self._git("cat-file", "-s", sha))
            if size > 1_048_576:
                raise HubError("Source file exceeds 1 MiB", 422)
            try:
                files[name] = self._git("cat-file", "blob", sha).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HubError("Source files must be UTF-8 text", 422) from exc
        validate_files(files)
        return Snapshot(revision, files)

    async def snapshot(self, folder: str, ref: str = "") -> Snapshot:
        validate_path(folder)
        async with self._lock:
            return await asyncio.to_thread(self._snapshot, folder, ref)

    def _commit(
        self, folder: str, files: Mapping[str, str | None], message: str, expected: str
    ) -> str:
        self._initialize()
        parent = self._git("rev-parse", "refs/heads/" + self.branch).decode().strip()
        if expected and parent != expected:
            raise HubError("Registry changed; reload before committing", 409)
        with tempfile.TemporaryDirectory(prefix="mcp-hub-index-") as temporary:
            env = {"GIT_INDEX_FILE": str(Path(temporary) / "index")}
            self._git("read-tree", parent, env=env)
            for name, content in files.items():
                path = folder + "/" + name
                if content is None:
                    self._git(
                        "update-index",
                        "-z",
                        "--index-info",
                        data=f"0 {'0' * 40}\t{path}\0".encode(),
                        env=env,
                    )
                else:
                    blob = (
                        self._git("hash-object", "-w", "--stdin", data=content.encode())
                        .decode()
                        .strip()
                    )
                    self._git(
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        "100644," + blob + "," + path,
                        env=env,
                    )
            tree = self._git("write-tree", env=env).decode().strip()
        created = self._git("commit-tree", tree, "-p", parent, "-m", message[:500]).decode().strip()
        self._git("update-ref", "refs/heads/" + self.branch, created, parent)
        return created

    async def commit(
        self, folder: str, files: Mapping[str, str | None], message: str, expected: str = ""
    ) -> str:
        if self.read_only:
            raise HubError(
                "Registry is read-only. Publish source changes to Git, then restart the server.",
                403,
            )
        validate_path(folder)
        validate_files(files)
        async with self._lock:
            return await asyncio.to_thread(self._commit, folder, files, message, expected)


class RemoteGitRegistry(LocalGitRegistry):
    """A remote Git branch is authoritative; publish only after a normal fast-forward push.

    Works with Bitbucket and other Git hosts. A failed push never reports a saved
    revision. The next fetch also resolves an ambiguous network failure safely.
    """

    def __init__(self, settings: Settings):
        super().__init__(
            settings.registry_local_path,
            settings.registry_branch,
            read_only=settings.registry_read_only,
        )
        self.remote = settings.registry_git_remote
        self.ssh = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
        ]
        if settings.registry_ssh_key:
            self.ssh += ["-o", "IdentitiesOnly=yes", "-i", settings.registry_ssh_key]
        if settings.registry_known_hosts:
            self.ssh += ["-o", "UserKnownHostsFile=" + settings.registry_known_hosts]

    def _git(self, *args: str, data: bytes | None = None, env: dict | None = None) -> bytes:
        return super()._git(
            *args,
            data=data,
            env={
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_SSH_COMMAND": shlex.join(self.ssh),
                **(env or {}),
            },
        )

    def _sync(self) -> str:
        super()._initialize()
        # Reject option-like branch names before constructing refspecs.
        self._git("check-ref-format", "--branch", self.branch)
        if "origin" not in self._git("remote").decode().splitlines():
            self._git("remote", "add", "origin", self.remote)
        else:
            self._git("remote", "set-url", "origin", self.remote)
        try:
            self._git(
                "fetch",
                "--no-recurse-submodules",
                "--tags",
                "origin",
                f"+refs/heads/{self.branch}:refs/remotes/origin/{self.branch}",
            )
        except HubError as exc:
            raise HubError(
                "Cannot read the Git registry. Check the repository, branch and deployment key.",
                502,
            ) from exc
        revision = self._git("rev-parse", f"refs/remotes/origin/{self.branch}").decode().strip()
        self._git("update-ref", "refs/heads/" + self.branch, revision)
        return revision

    def _remote_snapshot(self, folder: str, ref: str) -> Snapshot:
        self._sync()
        return super()._snapshot(folder, ref)

    async def snapshot(self, folder: str, ref: str = "") -> Snapshot:
        validate_path(folder)
        async with self._lock:
            return await asyncio.to_thread(self._remote_snapshot, folder, ref)

    def _remote_commit(
        self, folder: str, files: Mapping[str, str | None], message: str, expected: str
    ) -> str:
        self._sync()
        revision = super()._commit(folder, files, message, expected)
        try:
            # Never force: a concurrent remote edit must cause a conflict, not data loss.
            self._git("push", "origin", f"{revision}:refs/heads/{self.branch}")
        except HubError as exc:
            raise HubError(
                "Registry push failed or the branch changed. Reload the source and retry; check deployment-key write access.",
                409,
            ) from exc
        return revision

    async def commit(
        self, folder: str, files: Mapping[str, str | None], message: str, expected: str = ""
    ) -> str:
        if self.read_only:
            raise HubError(
                "Registry is read-only. Publish source changes to Git, then restart the server.",
                403,
            )
        validate_path(folder)
        validate_files(files)
        async with self._lock:
            return await asyncio.to_thread(self._remote_commit, folder, files, message, expected)
