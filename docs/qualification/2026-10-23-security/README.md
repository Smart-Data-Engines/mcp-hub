# Security qualification — 23 October 2026

Application/test checkpoint: `8dfd303`. The source-file hashes in `summary.json` identify the
tested code independently of subsequent documentation commits. Findings and upgrade behavior:
[security review](../../security-review-2026-10.md).

Local acceptance used CPython 3.14.4, uv 0.13.1, the frozen development lock, Node.js 22.22.1
and the console package lock. Backend: **247 passed**, zero failures/errors/skips; the three
Docker tests are a separate required CI job. Ruff, mypy, Prettier and console production build
passed. Python runtime and full npm dependency audits found zero known vulnerabilities after
the certifi update. The before/after Python audit reports are retained here.

`scripts/security_mutations.py` tested an archive of the committed source in disposable
directories. **23 harmful changes were detected; unchanged and neutral controls survived.**
The targeted assertion had to fail with no collection/setup errors. Each record includes source,
JUnit and output hashes. The original checkout was never mutated or restored from HEAD.

`reproductions.json` records the actual failing behaviors before the corresponding fixes.
An initial test-import error was corrected before those probes. A proposed full credential-key
migration was deliberately replaced with a narrow mapping for the two colliding names; ordinary
records retain their format. The migration-only test is not counted as a security finding.

Two test-environment issues were kept separate from application results. In the local tool
sandbox, a thread-backed password test stopped receiving its event-loop wakeup; the same
bounded test outside that sandbox passed. A property fixture then lacked the new catalog
validation marker and waited indefinitely for a call that had correctly been refused. The
fixture now represents a validated catalog and its wait is bounded. The full suite above was
run after both issues were resolved.

No live company IdP, production Redis, private registry or private adapter source was used.
MCP producers and state were synthetic and isolated; no shared development stack was replaced.
The workstation lacked Buildx and had limited disk space, so native Docker/browser acceptance
belongs to the repository's required `docker-acceptance` check on a fresh runner. Merge also
requires both Python jobs, console and CodeQL. Passing these checks is not a production rollout.

The first CI attempt (`40009550927`) passed both Python jobs, dependency scans, CodeQL and
native Docker isolation/recovery. Browser acceptance found a mobile overflow caused by the
new full revision string on an approval card. A scoped wrapping rule fixes it; the recorded
Chrome layout probe changed document width from 331 to 320 at a 320-pixel viewport.
`mobile-layout.json` identifies that follow-up's frontend source hashes separately from the
backend/mutation checkpoint. Console build and formatting passed again. The complete browser
suite is rerun in CI for the corrected head; the initial failure is not counted as acceptance.

Reproduce:

```sh
uv sync --frozen --extra dev
MCP_HUB_RUN_LIVE=1 uv run pytest -m 'not docker'
uv run ruff check src tests scripts/security_mutations.py deploy/operations.py deploy/restore_check.py
uv run mypy src/mcp_hub
uv run python scripts/security_mutations.py --output /tmp/mcp-hub-security-mutations-new
```

Use a new output directory and committed source for mutations. The helper uses real loopback
MCP producers; run it in an environment that permits local sockets and native worker threads.
