# Deployment

The reference runtime is a Linux Docker host. A company deployment supplies its
TLS reverse proxy, OIDC application, Git registry and audit sink.

1. Generate distinct random registration/upstream secrets, a Redis password and a
   Fernet encryption key. Keep `.env` outside Git and readable only by its owner.
2. Copy `.env.example`; set `ENVIRONMENT=production` and an HTTPS `HUB_PUBLIC_URL`.
3. Configure [company OIDC](identity-providers.md). Configure a separate GitHub
   repository using `REGISTRY_REPOSITORY=owner/repository`, `REGISTRY_BRANCH` and a
   token limited to the required repository contents/Git Data API operations.
   Initialize the registry branch with a first commit before creating adapters.
4. Set `DOCKER_GID` to the group of `/var/run/docker.sock`. Give the unprivileged hub
   UID access to its source/registry directories and that supplementary group.
5. Start the stack with `docker compose up --build -d`. Build the generic adapter
   image using `docker compose --profile build build upstream-image`.
6. Confirm Redis AOF/noeviction, `/health` and `/ready`. Provision the first admin.
7. Enable `ENABLE_SELF_SERVICE=true` only with the isolated topology and passing
   container acceptance tests. Register shared tools and grant read capabilities.

`make dev` is a separate localhost demonstration with a local bare Git registry.
It refuses to overwrite a company `.env` configuration.

## Network boundaries

- `state`: Redis and trusted hub controllers only. Redis requires a password.
- `ingress`: TLS proxy/control listener. `HUB_BIND_HOST` resolves to the hub's
  ingress interface only; it must not be `0.0.0.0` when self-service is enabled.
- One `upstream-*` bridge per adapter: that adapter and the hub controller(s).
  Adapters publish no ports and receive no Docker socket or Redis configuration.
- Port 8001 is the registration-only listener. It exposes no administration, OAuth,
  credentials, metrics or MCP gateway routes. Managed adapters receive per-server
  derived secrets, bound to the assigned name, address and code snapshot.

The sample Compose file publishes the control listener only on 127.0.0.1. A TLS
proxy on the host can forward to it. Set `TRUSTED_PROXY_IPS` to the actual trusted
proxy addresses/CIDRs when forwarding client IPs; forwarding headers are ignored
by default. Preserve the canonical Host/Origin for MCP requests.

Adapters have normal outbound bridge NAT to reach their source systems. Docker
bridge isolation must remain enabled; publishing adapter or state ports, enabling
unprotected direct routing, or adding shared networks changes the trust boundary.
Run the container probes in the target environment rather than inferring isolation
from the YAML file. The trusted controller's Docker API access is host-level authority.

## Multiple replicas and deployment

Each controller needs an adequate descriptor budget. The reference Compose sets
both nofile limits to 65536: 1024 is insufficient for 1000 client connections plus
listeners, Redis and upstream sockets. Preserve this limit on every replica.

Replicas share Redis, encryption/master secrets, canonical public URL and registry.
Each has its own upstream MCP sessions and reconciles the shared registry/catalog.
For Docker, give every controller a unique container name, ingress DNS alias and
`HUB_BIND_HOST`/`RUNTIME_HUB_CONTAINER`; do not scale the sample's fixed container
name unchanged. Each controller joins the adapter networks as it reconciles them.

For blue-green deployment, start the new controller, wait for `/ready`, switch the
load balancer, and send SIGTERM to the old controller. Readiness becomes false on
the signal tick. New tool calls are rejected while accepted calls finish within
`SHUTDOWN_GRACE_PERIOD`; overdue calls receive an explicit shutdown outcome.

Reuse the Store namespace within a compatible release. Test rollback against a
restored backup before introducing any incompatible state migration.

## Acceptance gate

Configure real IdP claims, source-system identities, certificate trust, grants,
registry permissions, retention and operational owners. Re-run isolation, recovery,
deployment-under-traffic and workload measurements against that topology. Local
demo results are a reference profile, not acceptance of an untested company deployment.
