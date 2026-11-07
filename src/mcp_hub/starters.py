"""Versioned public starters, independent of the customer's source registry."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any

import yaml

from .models import HubError, ServerDefinition
from .registry import Registry, Snapshot

VERSION = "1.0.0"
SOURCE_VERSIONS = {"1.0.0": "mcp_hub.starter_code.v1"}
CATALOG: dict[str, dict[str, Any]] = {
    "demo": {
        "name": "Demo",
        "description": "A working example with your verified Hub identity. No external account needed.",
        "tools": ["hello", "who_am_i"],
        "account_required": False,
    },
    "github": {
        "name": "GitHub",
        "description": "Read a GitHub.com repository, its issues and pull requests using your own account or a shared connection.",
        "tools": [
            "get_repository",
            "list_issues",
            "get_issue",
            "list_pull_requests",
            "get_pull_request",
        ],
        "account_required": True,
    },
}


def catalog() -> list[dict]:
    return [
        {"id": key, "version": VERSION, "read_only": True, **value}
        for key, value in CATALOG.items()
    ]


async def source_snapshot(registry: Registry, definition: ServerDefinition) -> Snapshot:
    if definition.starter_id:
        return snapshot(definition)
    return await registry.snapshot(f"{definition.owner}/{definition.name}", definition.pinned_ref)


def snapshot(definition: ServerDefinition) -> Snapshot:
    if definition.starter_id not in CATALOG or definition.starter_version not in SOURCE_VERSIONS:
        raise HubError("This starter version is not available in this Hub release", 409)
    root = files(SOURCE_VERSIONS[definition.starter_version])
    source = {
        "server.py": root.joinpath(
            "github.py" if definition.starter_id == "github" else "demo.py"
        ).read_text(),
        "requirements.txt": "mcp==1.30.0\n",
        "manifest.yaml": yaml.safe_dump(
            {
                "name": definition.name,
                "owner": definition.owner,
                "contract_version": 1,
                "starter": definition.starter_id,
                "starter_version": definition.starter_version,
            }
        ),
        "docker.yaml": yaml.safe_dump(
            {"memory": f"{definition.memory_mb}m", "cpus": str(definition.cpus)}
        ),
        "env.yaml": "env: []\nuser_env: []\n",
        "README.md": "# "
        + CATALOG[definition.starter_id]["name"]
        + " starter\n\n"
        + "This public example is included with MCP Hub. All tools are read-only.\n"
        + "To customize it, create a Custom Python server and copy the example files into its registry folder.\n"
        + "Keep the manifest.yaml generated for your Custom server (do not replace it with this starter manifest). Keep serve(mcp).\n"
        + "Commit the files and restart the server to apply the new source.\n",
    }
    if definition.starter_id == "github":
        source["requirements.txt"] += "httpx==0.28.1\n"
        source["github_client.py"] = root.joinpath("github_client.py").read_text()
        source["env.yaml"] = (
            "env: [GITHUB_TOKEN, GITHUB_REPOSITORY]\nuser_env: [token, repository]\n"
        )
        source["README.md"] += (
            "\n## GitHub connection\n\nUse a fine-grained token restricted to the selected repository, with Metadata, Issues and Pull requests read access.\n"
            "Personal fields: token and repository (owner/repository). Shared administrator fields: GITHUB_TOKEN and GITHUB_REPOSITORY.\n"
            "The Hub's Connection form saves these encrypted and checks account/repository/issue/pull-request read access.\n"
            "Every tool requires the trusted credentials identity argument; partial personal fields never borrow shared values.\n"
            "GitHub.com is the fixed API host. Lists return a bounded first page, with kind distinguishing issues from pull requests.\n"
            "API reference: https://docs.github.com/en/rest\n"
        )
    revision = hashlib.sha256(json.dumps(source, sort_keys=True).encode()).hexdigest()[:40]
    return Snapshot(revision, source)


def source_location(definition: ServerDefinition) -> dict:
    return {
        "kind": "starter",
        "provider": "Included starter",
        "repository": CATALOG[definition.starter_id]["name"],
        "repository_url": None,
        "folder_url": None,
        "folder": definition.starter_id,
        "branch": definition.starter_version,
        "reference": definition.starter_version,
        "pinned": True,
        "editing_enabled": False,
        "version": definition.starter_version,
    }
