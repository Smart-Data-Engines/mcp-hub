"""Remote Git behavior checked against an independent Git producer and reader."""

import asyncio
import subprocess

import pytest

from mcp_hub.models import HubError
from mcp_hub.registry import RemoteGitRegistry


def git(directory, *args):
    return subprocess.run(
        ["git", "-C", str(directory), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def remote(tmp_path, settings):
    author = tmp_path / "author"
    author.mkdir()
    git(author, "init", "-b", "master")
    git(author, "config", "user.name", "Independent author")
    git(author, "config", "user.email", "author@example.test")
    (author / "README.md").write_text("Private registry\n")
    git(author, "add", "README.md")
    git(author, "commit", "-m", "Initial source")
    origin = tmp_path / "origin.git"
    git(tmp_path, "clone", "--bare", str(author), str(origin))
    git(author, "remote", "add", "origin", str(origin))
    settings.registry_backend = "git"
    settings.registry_git_remote = str(origin)
    settings.registry_local_path = str(tmp_path / "hub-cache.git")
    settings.registry_branch = "master"
    return RemoteGitRegistry(settings), author, origin, settings


async def test_remote_batch_commit_then_independent_edit_and_immutable_snapshot(remote):
    registry, author, origin, _ = remote
    initial = await registry.snapshot("owner/adapter")
    assert not initial.files
    created = await registry.commit(
        "owner/adapter",
        {"server.py": "print('exact')\n", "requirements.txt": "mcp>=1.30,<2\n"},
        "Create adapter",
        initial.commit,
    )
    assert git(origin, "show", created + ":owner/adapter/server.py") == "print('exact')"
    assert git(origin, "show", created + ":README.md") == "Private registry"
    git(author, "pull", "--ff-only", "origin", "master")
    (author / "owner/adapter/server.py").write_text("print('external author')\n")
    git(author, "add", ".")
    git(author, "commit", "-m", "External edit")
    git(author, "push", "origin", "master")
    snapshot = await registry.snapshot("owner/adapter")
    assert snapshot.files["server.py"] == "print('external author')\n"
    assert (await registry.snapshot("owner/adapter", created)).files[
        "server.py"
    ] == "print('exact')\n"
    with pytest.raises(HubError, match="reload"):
        await registry.commit("owner/adapter", {"server.py": "stale"}, "Stale edit", created)
    assert git(origin, "show", "master:owner/adapter/server.py") == "print('external author')"


async def test_rejected_push_never_claims_success_or_leaks_an_unpublished_local_revision(remote):
    registry, _, origin, _ = remote
    initial = await registry.snapshot("owner/adapter")
    hook = origin / "hooks/pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    with pytest.raises(HubError, match="push failed"):
        await registry.commit(
            "owner/adapter", {"server.py": "not published"}, "Rejected", initial.commit
        )
    snapshot = await registry.snapshot("owner/adapter")
    assert snapshot.commit == initial.commit and snapshot.files == {}
    assert git(origin, "rev-parse", "master") == initial.commit


async def test_two_remote_writers_cannot_overwrite_each_others_changes(remote, tmp_path):
    first, _, origin, settings = remote
    initial = await first.snapshot("owner/adapter")
    settings.registry_local_path = str(tmp_path / "second-cache.git")
    second = RemoteGitRegistry(settings)
    await second.snapshot("owner/adapter")
    results = await asyncio.gather(
        first.commit("owner/adapter", {"server.py": "first"}, "First writer", initial.commit),
        second.commit("owner/adapter", {"server.py": "second"}, "Second writer", initial.commit),
        return_exceptions=True,
    )
    assert sum(isinstance(result, str) for result in results) == 1
    assert sum(isinstance(result, HubError) and result.status == 409 for result in results) == 1
    winner = next(result for result in results if isinstance(result, str))
    assert git(origin, "rev-parse", "master") == winner
    assert git(origin, "rev-parse", "master^") == initial.commit


async def test_read_only_registry_can_fetch_and_cannot_create_a_commit(remote):
    _, _, origin, settings = remote
    settings.registry_read_only = True
    registry = RemoteGitRegistry(settings)
    before = await registry.snapshot("owner/adapter")
    with pytest.raises(HubError) as error:
        await registry.commit(
            "owner/adapter", {"server.py": "not published"}, "Disallowed", before.commit
        )
    assert error.value.status == 403 and "read-only" in error.value.message
    assert git(origin, "rev-parse", "master") == before.commit
    assert (await registry.snapshot("owner/adapter")).commit == before.commit
