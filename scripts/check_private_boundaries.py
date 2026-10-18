"""Reject private/generated files in the public index and outgoing Git history."""

import argparse
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = "smart-data-engines-mcp-registry"
PRIVATE_DIRS = {
    PRIVATE,
    ".local",
    ".venv",
    "node_modules",
    "__pycache__",
    "test-results",
    "playwright-report",
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], stderr=subprocess.PIPE)


def check_entries(raw: bytes, *, tree: bool = False) -> None:
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        metadata, encoded_path = entry.split(b"\t", 1)
        path = PurePosixPath(encoded_path.decode())
        if (
            set(path.parts) & PRIVATE_DIRS
            or path.name in {"mcp-hub-product-spec.md", "id_rsa", "id_ed25519"}
            or (path.name.startswith(".env") and path.name != ".env.example")
            or metadata.split()[0] not in {b"100644", b"100755"}
        ):
            kind = "commit" if tree else "index"
            raise SystemExit(f"Private/generated file or link in public {kind}: {path}")


def check_exclusions() -> None:
    for path in [
        PRIVATE + "/.privacy-probe",
        "mcp-hub-product-spec.md",
        ".local/probe",
        ".venv",
        ".env",
        ".env.production",
        "frontend/.env",
    ]:
        result = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "--no-index", "-q", path])
        if result.returncode:
            raise SystemExit(f"Private path must be excluded by .gitignore: {path}")
    patterns = [
        line.strip()
        for line in (ROOT / ".dockerignore").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    required = {PRIVATE, "mcp-hub-product-spec.md", ".local", ".env", ".env.*", ".venv", ".git"}
    if not required <= {line.strip("/") for line in patterns} or any(
        line.startswith("!") for line in patterns
    ):
        raise SystemExit(
            "Docker context must explicitly exclude private paths without re-inclusion rules."
        )


def check_push_history() -> None:
    checked = set()
    for line in sys.stdin:
        fields = line.split()
        if len(fields) != 4 or any(not re.fullmatch(r"[0-9a-f]{40,64}", fields[i]) for i in (1, 3)):
            raise SystemExit("Invalid pre-push reference input")
        local, remote = fields[1], fields[3]
        if set(local) == {"0"}:
            continue
        revisions = [local]
        if set(remote) != {"0"}:
            exists = subprocess.run(
                ["git", "-C", str(ROOT), "cat-file", "-e", remote + "^{commit}"],
                capture_output=True,
            )
            if exists.returncode == 0:
                revisions.append("^" + remote)
        for commit in git("rev-list", *revisions).decode().splitlines():
            if commit not in checked:
                check_entries(git("ls-tree", "-r", "-z", commit), tree=True)
                checked.add(commit)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pre-push",
        action="store_true",
        help="Also check every outgoing commit, including files later removed",
    )
    args = parser.parse_args()
    check_entries(git("ls-files", "--stage", "-z"))
    check_exclusions()
    if args.pre_push:
        check_push_history()
    print(
        "Private source, specification, credentials and local state excluded from public Git/Docker."
    )
