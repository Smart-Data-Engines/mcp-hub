"""Generic upstream image entrypoint: installation failure prevents execution."""

import os
import subprocess
import sys

import certifi


def main() -> None:
    subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", "/tmp/server-venv"], check=True
    )
    python = "/tmp/server-venv/bin/python"
    subprocess.run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-cache-dir",
            "--disable-pip-version-check",
            "--use-deprecated=legacy-certs",
            "--cert",
            os.environ.get("PIP_CERT") or certifi.where(),
            "-r",
            "/server/requirements.txt",
        ],
        check=True,
    )
    os.execv(python, [python, "/server/server.py"])


if __name__ == "__main__":
    main()
