# MCP Hub

[![CI](https://github.com/Smart-Data-Engines/mcp-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/Smart-Data-Engines/mcp-hub/actions/workflows/ci.yml)

A shared MCP endpoint for an organization's tools, with company sign-in, live
permissions, encrypted credentials, audit and an isolated Python server runtime.

Clients connect to `/mcp`. Tool authors publish a folder to a Git registry. The
console manages access, source files, credentials and server lifecycle.

## Try it locally

Prerequisites: Python 3, Docker Engine with Compose, and access to the Docker
daemon. The development launcher can use `sudo -n docker` when configured.

```sh
make dev
```

Open **http://localhost:8000/admin/**, continue with company sign-in, choose
**Admin** in the local test provider. The launcher
generates `.env` with fresh secrets, enables Redis AOF, provisions the first admin
and starts two read-only demonstration adapters. Their data stays on your machine.
The **Developer** and **Analyst** identities join the default read-only group.

To share a server, open **MCP servers → server → Access**, choose a person and
**Save access**. The console shares a restricted server with that person and saves
their permissions together. Groups and personal credentials use guided forms.
See the [console guide](docs/console-guide.md) for team access and client setup.

The demonstration identity provider deliberately does not authenticate users and
is bound to localhost. Company deployments replace it with their own OIDC provider.

To stop the local stack, run:

```sh
docker compose -f compose.yaml -f compose.demo.yaml down
```

The Redis volume and `.local/` registry/source files persist across restarts.

## Included

- Official MCP Streamable HTTP transport, stateless client-facing requests,
  persistent upstream sessions and a shared versioned Redis tool catalog.
- Embedded OAuth authorization server: discovery, dynamic client registration,
  authorization code + S256 PKCE, rotating refresh tokens, service clients and
  reverse-index token revocation. Access tokens are opaque and stored by hash.
- Configurable company OIDC login: Google Workspace, Microsoft Entra ID, Keycloak,
  Okta, Auth0, GitLab or a generic OIDC issuer. No application password database.
- Atomic permission snapshots, groups, personal grant/deny overrides,
  read/write/destructive capabilities, private/shared/public server visibility,
  and admin/manager roles.
- Authenticated encryption for personal credentials and Global Env; request
  credential overrides; server-enforced policies; spoofed identity removal;
  secret redaction in tool responses and structured logs.
- Hardened Docker containers from one generic image, a network per server,
  separate state and ingress networks, scoped registration/upstream secrets,
  immutable Git snapshots, batch commits, fresh-source restart and recovery.
- Per-tool rate limits, daily budgets, argument guardrails, idempotent writes,
  out-of-band human approval and optional four-eyes review.
- Durable bounded audit outbox, optional Elasticsearch/OpenSearch-compatible sink,
  Prometheus metrics, optional OTLP traces, circuit breakers and graceful drain.
- React/TypeScript console with guided connection fields, source-repository details,
  optional code browsing/editing and the same OAuth login as MCP clients.

The optional client configuration distribution and non-MCP service adapters are
not included. Service-specific OAuth credential connectors are a separate extension;
the included credential sources are request headers, the encrypted personal store
and administrator-managed Global Env.

## Company deployment

Copy `.env.example` to `.env` and follow [the deployment guide](docs/deployment.md).
Choose the provider, issuer and client credentials through environment variables.
[Provider examples](docs/identity-providers.md) cover the discovery and callback
settings for each supported provider.

Production uses HTTPS, an authenticated Redis primary with AOF/noeviction, a separate
Git source registry (GitHub API or SSH Git), and isolated Docker networks. Self-service stays disabled
until the runtime configuration passes its startup checks. The controller's Docker
socket access is part of the trusted operator boundary.

## Development and verification

Python 3.13+ and Node.js 22 are supported. Exact dependencies are in `uv.lock` and
`frontend/package-lock.json`.

```sh
uv sync --frozen --extra dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src/mcp_hub
MCP_HUB_RUN_LIVE=1 uv run pytest -m 'not docker'
cd frontend
npm ci
npm run build
npm test
```

Browser tests require the local stack. They use installed Google Chrome locally
(`CHROME_EXECUTABLE` overrides its path) or Playwright Chromium in CI. Container
acceptance tests need Docker socket access:

```sh
MCP_HUB_RUN_DOCKER=1 uv run pytest tests/integration/test_docker_runtime.py
```

Tests use Redis with actual Lua support, real Git, actual TCP MCP producers and the
official MCP client. Docker tests probe isolation from inside runtime-created servers
and test native Redis backup/restore. See [the acceptance ledger](docs/implementation.md)
for the measured validation status and outstanding deployment gates.

Additional references: [API](docs/api.md), [server-author contract](docs/server-authoring.md),
[operations and recovery](docs/operations.md).

For pull requests and the local publication guard, see [Contributing](CONTRIBUTING.md).
Report vulnerabilities using [the security policy](SECURITY.md).
