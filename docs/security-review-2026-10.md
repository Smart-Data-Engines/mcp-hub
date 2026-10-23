# Security review, October 2026

Scope: controller authorization, OIDC/OAuth, approval/replay, adapter boundaries, bounded state,
reference containers, console and locked dependencies. The baseline was `dfc48ac`.
Tests use synthetic identities, isolated state and loopback MCP producers. This is not a
penetration test of a company's IdP, production host or source-system accounts.

## Changes

| Boundary | Result |
| --- | --- |
| Tool capabilities | Unannotated tools use the destructive default; old cached categories do not restore read permission. |
| Adapter schemas | Typed MCP responses and JSON limits remain enforced; adapter-provided regex/recursive output schemas are not executed in the controller. |
| Catalog failure | Cached metadata remains discoverable, while new dispatch waits for successful validation. |
| Approvals and cached writes | Connection/policy/client/revision changes cannot reuse prior consent or replay another context's result. Current credential policy is checked before replay. |
| OIDC administration | A subject's old verified-email administrator binding is removed when its claim changes; `azp` is checked for single and multiple audiences. |
| Personal state | Atomic credential/preference quotas, document/header bounds, isolated bookkeeping names and a shared mutation rate limit. |
| OAuth registration | Atomic capacity, expiry of unused registrations, renewal during valid exchange and refusal when expiry races code exchange. |
| Untrusted declarations | Bounded YAML without aliases; snapshot count/size preflight before reading blobs. |
| Audit and logs | Bounded audit records retain explicit truncation metadata; oversized log details are withheld. |
| Configuration | Unknown environment names, non-finite server timeouts and access tokens outliving their revocation index are rejected. Server owners cannot exceed the deployment call ceiling. |
| TLS | Updated certifi, explicit curated trust for company CAs and worker installation; runtime and console dependency audits added to CI. |

The independent Python audit found **GHSA-6q48-6c7w-9gw2** in certifi 2026.7.22 even though
the repository's Dependabot alert list was empty at inspection. The lock now uses certifi
2026.10.23 and the dependency floor is 2026.10.19. The advisory concerns compromised CA keys;
it is not evidence that this deployment was intercepted.
[Maintainer advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2).

## Verification

The regression tests first failed against the old behaviors, including real MCP output-schema
evaluation, dispatch with read-only grants, changed approval contexts, persistent registration
growth and oversized audit records. The detailed tests are in `test_execution_context.py`,
`test_untrusted_definitions.py`, `test_security_capacity.py` and `test_trust_boundary.py`.
The existing property suite retains valid catalogs and uses bounded synchronization waits so a
rejected request cannot hang a test indefinitely.

Reproduce the backend with `MCP_HUB_RUN_LIVE=1 uv run pytest -m 'not docker'`, plus Ruff and mypy
as in the README. Console build and browser/Docker acceptance run in the required CI checks.
The publication guard checks the index and outgoing history for private/generated artifacts.
[Qualification details and mutation results](qualification/2026-10-23-security/README.md)
record the source identity, failing reproductions and controls.

## Upgrade and operational boundaries

Upgrade controllers together and rebuild the worker image. Previously unannotated adapters
need explicit, reviewed annotations for read-only grants. A cached catalog lacking the new
validation marker cannot dispatch until rediscovery. Old write records refuse context reuse;
let their TTLs expire and inspect uncertain outcomes before a new operation. New registration
quotas preserve legacy registrations rather than silently deleting client configuration.

Personal preference reset means removing the explicit preference; deleting a credential still
preserves “only mine”. Audit truncation is visible; deployments needing more detail may raise
`MAX_AUDIT_EVENT_BYTES` within its bound and size the outbox accordingly. Review the new defaults
in `.env.example`. In-flight calls and cached operations have finite windows, not permanent
exactly-once guarantees. Existing live deployments require their own rollout and site acceptance.

Adapters intentionally receive delegated credentials and execute authored code. Container
isolation does not turn arbitrary code into a trustworthy source-system client. Company IdP
policy, cloud metadata egress, public probes, Git history/storage quotas and host patching remain
operator responsibilities, as described in the security/deployment guides.

Protocol references: [MCP tool annotations](https://modelcontextprotocol.io/specification/2025-11-25/schema#toolannotations),
[OIDC token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[pip certificate stores](https://pip.pypa.io/en/stable/topics/https-certificates/).
