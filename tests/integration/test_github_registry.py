import base64
import json

import httpx
import pytest

from mcp_hub.models import HubError, ServerDefinition
from mcp_hub.registry import GitHubRegistry
from mcp_hub.upstream import scaffold


async def test_github_snapshot_pins_one_commit_and_reads_only_its_folder(settings):
    settings.registry_repository, settings.registry_token = "example/registry", "test-only-token"
    files = {"server.py": "print('source')", "requirements.txt": "mcp>=1.30,<2"}
    paths = []

    def host(request):
        paths.append(request.url.path)
        assert request.headers["authorization"] == "Bearer test-only-token"
        suffix = request.url.path.removeprefix("/repos/example/registry/")
        if suffix == "commits/main":
            return httpx.Response(200, json={"sha": "a" * 40, "commit": {"tree": {"sha": "tree"}}})
        if suffix == "git/trees/tree":
            return httpx.Response(
                200,
                json={
                    "tree": [
                        {
                            "path": "owner/adapter/" + name,
                            "sha": name,
                            "mode": "100644",
                            "type": "blob",
                            "size": len(content),
                        }
                        for name, content in files.items()
                    ]
                    + [
                        {
                            "path": "other/private/secret.py",
                            "sha": "do-not-fetch",
                            "mode": "100644",
                            "type": "blob",
                        }
                    ]
                },
            )
        if suffix.startswith("git/blobs/"):
            name = suffix.removeprefix("git/blobs/")
            return httpx.Response(
                200, json={"content": base64.b64encode(files[name].encode()).decode()}
            )
        raise AssertionError(request.url)

    async with httpx.AsyncClient(transport=httpx.MockTransport(host)) as client:
        snapshot = await GitHubRegistry(settings, client).snapshot("owner/adapter")
    assert snapshot.commit == "a" * 40 and snapshot.files == files
    assert not any("do-not-fetch" in path for path in paths)


@pytest.mark.parametrize("conflict", [False, True])
async def test_github_batch_commit_uses_one_tree_one_commit_and_nonforced_ref(settings, conflict):
    settings.registry_repository, settings.registry_token = "example/registry", "test-only-token"
    writes = []

    def host(request):
        suffix = request.url.path.removeprefix("/repos/example/registry/")
        data = json.loads(request.content) if request.content else {}
        if request.method != "GET":
            writes.append((request.method, suffix, data))
        if suffix == "git/ref/heads/main":
            return httpx.Response(200, json={"object": {"sha": "parent"}})
        if suffix == "git/commits/parent":
            return httpx.Response(200, json={"tree": {"sha": "old-tree"}})
        if suffix == "git/trees":
            return httpx.Response(201, json={"sha": "new-tree"})
        if suffix == "git/commits":
            return httpx.Response(201, json={"sha": "new-commit"})
        if suffix == "git/refs/heads/main":
            return httpx.Response(422 if conflict else 200, json={})
        raise AssertionError(suffix)

    async with httpx.AsyncClient(transport=httpx.MockTransport(host)) as client:
        registry = GitHubRegistry(settings, client)
        if conflict:
            with pytest.raises(HubError) as raised:
                await registry.commit(
                    "owner/adapter", {"server.py": "new", "env.yaml": None}, "one change", "parent"
                )
            assert raised.value.status == 409
        else:
            assert (
                await registry.commit(
                    "owner/adapter", {"server.py": "new", "env.yaml": None}, "one change", "parent"
                )
                == "new-commit"
            )
    assert [path for _, path, _ in writes] == ["git/trees", "git/commits", "git/refs/heads/main"]
    assert len(writes[0][2]["tree"]) == 2
    assert writes[1][2]["parents"] == ["parent"]
    assert writes[2][2]["force"] is False


async def test_registering_existing_source_preserves_code_instead_of_scaffolding_over_it(
    harness, monkeypatch
):
    runtime = harness.hub.runtime
    monkeypatch.setattr(runtime, "_require", lambda: None)
    files = scaffold("imported", "alice")
    files["server.py"] = "custom source must survive import"
    revision = await runtime.registry.commit("alice/imported", files, "existing authored code")
    await runtime.create(ServerDefinition(name="imported", owner="alice"))
    snapshot = await runtime.registry.snapshot("alice/imported")
    assert (
        snapshot.commit == revision
        and snapshot.files["server.py"] == "custom source must survive import"
    )
