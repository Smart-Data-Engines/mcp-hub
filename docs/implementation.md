# Implementation and acceptance ledger

The local product specification is version 2.0 (2026-09-07). It remains ignored by
Git. This ledger records implementation and validation without copying its text.

## Scope

The implementation targets the mandatory gateway, embedded OAuth authorization
server, configurable OIDC bridge, ACL, encrypted credentials, Git registry,
isolated Docker runtime and administration console. The optional non-MCP adapters
and client configuration distribution are outside this release.

## Architecture

- Python 3.13+ / Starlette / official MCP SDK v1 maintenance line (upper bound `<2`).
- Opaque, hashed bearer tokens; Redis Lua for single-use codes, refresh rotation,
  reverse-index revocation, rate windows and unique server reservations.
- One atomic ACL snapshot per request, with capabilities and visibility applied
  during both listing and invocation. No per-user permission cache.
- Long-lived MCP client sessions owned by dedicated tasks; catalog shared in Redis.
- OIDC issuer, client and provider name selected using `.env`. Google Workspace,
  Microsoft Entra ID, Keycloak, Okta, Auth0, GitLab and generic OIDC share signature,
  issuer, audience, nonce and browser-state verification.
- Fernet authenticated encryption, overlapping key rotation, bounded secret
  redaction, transport byte limits and a durable bounded Redis audit outbox.
- GitHub Git Data API for atomic source commits; real local bare Git for the demo.
- Public control listener binds only to the ingress interface. A second listener
  exposes registration and unregistration only. Managed upstreams receive derived
  per-server secrets, never the registration/upstream master secrets.
- Each Docker upstream has its own bridge, no published ports, read-only source and
  root filesystem, non-root UID, dropped capabilities, process/CPU/memory limits,
  and a temporary filesystem. Redis uses a separate, password-protected network.
- React/TypeScript SPA with CodeMirror, company OAuth login, personal credentials,
  server lifecycle/source/env, access sources, groups, roles, bots and approvals.

## Acceptance evidence

| Milestone | Implemented behavior | Verification |
|---|---|---|
| M0 | Streamable HTTP, shared registry/catalog, routing, probes and local stack | Official MCP client against actual TCP producers; 20 list requests perform zero upstream HTTP calls; second replica restores before ready |
| M1 | OIDC bridge, discovery/DCR, PKCE, opaque tokens, rotating refresh, bots and indexed revocation | Valid/rejected identities across seven provider choices; parallel code/refresh attempts; no-keyspace-scan revocation |
| M2 | Group/grant/deny/visibility/capabilities, roles and permission sources | HTTP tests plus property invariants; grant overrides deny; read mask rejects writes; last-admin/default-group protection |
| M3 | Encrypted personal/global credentials, source priority, identity injection and key rotation | Header precedence, spoof removal, empty/partial credential refusal, explicit decryption errors, different sources, retained running-secret snapshot |
| M4 | Git registry, runtime lifecycle/editor, scoped secrets and isolated hardened containers | Real Git and GitHub HTTP contract; in-container state/peer/control probes; 128 MiB hard limit; fresh-source and same-commit restart; failed installation stops execution |
| M5 | Redaction/cap/rate/daily guardrails, idempotency and durable audit outbox | Real upstream effect counter remains one for concurrent writes; blocked calls audited; sink outage replay; explicit overflow counter |
| M6 | Drain, warm catalog recovery, circuit breakers, transport caps, backup and telemetry | Native Redis DUMP/restore preserves permissions, encrypted values/indexes and outbox; expired entries/session tokens omitted; signal-time readiness measurement and active-call drain |
| M7 | Human/four-eyes approval, pinned refs and multiple controllers | Browser-bound approval proof; new server joins a running second Docker controller; stop detaches both; stable client endpoint survives cutover |

The suite includes 23 property invariants with 100 generated cases on open domains
and exhaustive cases where a domain is smaller. State is exercised with actual Lua,
not a mocked sequence of reads/writes. Container tests use native Redis and probe
the network from inside untrusted-role containers.

The Chrome tests cover real OIDC login/consent, desktop/mobile navigation, a two-file
batch commit, server start, log viewing and cleanup. Source-file hashes in the tested
image were compared with the workspace. Exact environment, counts, artifact IDs and
measurements are recorded in [verification.md](verification.md).

Client delegation is separate from the user's role: ordinary MCP client tokens
cannot manage Hub configuration. First-party console tokens and explicitly enabled
management service clients still need the appropriate user role/ownership.

## Remaining deployment gates and optional scope

- Real company IdP tenant/claims, registry token, TLS/CA, proxy topology, source-system
  delegation, audit sink retention and operational owners need site acceptance.
- The GitHub production adapter is covered by an HTTP contract test; no live company
  repository or provider account was modified by automated tests.
- Service-specific OAuth credential connectors and the explicitly optional client
  package distribution/non-MCP adapters are outside 0.1.0. Manual encrypted credentials,
  request headers and Global Env work without those extensions.
- The local workload is a reference profile. It does not qualify arbitrary tenant
  sizes, database tool workloads, reverse proxies or host network policies.

## Local validation incident

The first Docker build exhausted writable space on the workstation. A formatter
then truncated newly created Python files. All 21 affected files were recovered
from 24 recorded patch batches into a separate temporary tree, parsed with Python's
AST parser, and restored. Full verification and image rebuilding were repeated
after recovery. Temporary dependency environments were moved under `/tmp`; these
are regenerable from the committed lockfiles. No shared Docker volumes were pruned.
