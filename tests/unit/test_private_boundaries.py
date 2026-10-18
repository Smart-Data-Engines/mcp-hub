"""Exercise publication boundaries with real Git indexes and commit histories."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture
def public_repo(tmp_path):
    root = Path(__file__).resolve().parents[2]
    repo = tmp_path / "public"
    repo.mkdir()
    (repo / "scripts").mkdir()
    for name in [".gitignore", ".dockerignore", "scripts/check_private_boundaries.py"]:
        shutil.copyfile(root / name, repo / name)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


def run_git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)


def guard(repo, *, push=None):
    return subprocess.run(
        [
            sys.executable,
            str(repo / "scripts/check_private_boundaries.py"),
            *(["--pre-push"] if push else []),
        ],
        input=push,
        capture_output=True,
        text=True,
    )


def test_public_example_environment_is_allowed(public_repo):
    environment = public_repo.parent / "environment"
    environment.mkdir()
    (public_repo / ".venv").symlink_to(environment, target_is_directory=True)
    (public_repo / ".env.example").write_text("TOKEN=REPLACE_ME\n")
    run_git(public_repo, "add", ".env.example", ".gitignore", ".dockerignore", "scripts")
    assert guard(public_repo).returncode == 0


@pytest.mark.parametrize(
    "name",
    [
        "smart-data-engines-mcp-registry/owner/tool/server.py",
        "mcp-hub-product-spec.md",
        ".env.production",
        ".local/state.json",
        "keys/id_ed25519",
    ],
)
def test_forced_staging_of_private_files_is_rejected(public_repo, name):
    path = public_repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("private fixture\n")
    run_git(public_repo, "add", "-f", name)
    assert guard(public_repo).returncode != 0


@pytest.mark.parametrize("change", ["include_all", "remove_secret_exclusion"])
def test_docker_rules_cannot_reinclude_private_files(public_repo, change):
    path = public_repo / ".dockerignore"
    original = path.read_text()
    path.write_text(
        original + "\n!**\n" if change == "include_all" else original.replace(".env.*\n", "")
    )
    assert guard(public_repo).returncode != 0


def test_removing_a_private_file_later_does_not_make_its_history_publishable(public_repo):
    private = public_repo / ".local/private.py"
    private.parent.mkdir()
    private.write_text("private history fixture\n")
    run_git(public_repo, "add", "-f", str(private))
    identity = ["-c", "user.name=Publication test", "-c", "user.email=test@example.test"]
    run_git(public_repo, *identity, "commit", "-qm", "Accidentally include private data")
    run_git(public_repo, "rm", "-q", ".local/private.py")
    run_git(public_repo, *identity, "commit", "-qm", "Remove from current tree")
    head = run_git(public_repo, "rev-parse", "HEAD").decode().strip()
    assert guard(public_repo).returncode == 0
    result = guard(public_repo, push=f"refs/heads/main {head} refs/heads/main {'0' * 40}\n")
    assert result.returncode != 0 and "commit" in result.stderr
