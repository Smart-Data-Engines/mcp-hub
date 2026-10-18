# Internal deployment

Use `compose.yaml` with `deploy/compose.internal.yaml`. Generate a private `.env`
on the deployment host; never ship a developer's environment or demo Redis state.
Keep the application port on loopback and terminate HTTPS on an explicitly private
or VPN interface. The internal overlay separates the container listener (8000)
from the configurable host `HUB_PORT` and bounds controller/store resources.

For an SSH Git registry, configure `REGISTRY_BACKEND=git`, `REGISTRY_GIT_REMOTE`,
`REGISTRY_BRANCH`, `REGISTRY_LOCAL_PATH`, `REGISTRY_SSH_KEY` and
`REGISTRY_KNOWN_HOSTS`. The overlay mounts only the controller's dedicated key and
pinned host keys. Give that identity repository-scoped read/write access when
console source editing is needed. A read-only access key also works: set
`REGISTRY_READ_ONLY=true`, publish code changes separately through Git and restart
the server from the console. Source location and optional file browsing remain available.
Worker containers never receive its SSH key, the Redis password or the Docker socket.

The remote Git branch is authoritative. Source reads fetch its current revision;
writes use normal fast-forward pushes. A concurrent edit or rejected push returns
an error and requires reloading; the hub never forces a remote branch update or
reports an unpublished local commit as saved. A pre-cloned bare cache can be
installed before credentials are authorized, but remote fetch/push must be verified
before enabling source editing.

Choose Google and an allowed Workspace domain through environment variables. Set
`ADMIN_EMAILS` to the intended administrator's verified email. Register an Internal
Google web application with the exact `HUB_PUBLIC_URL/oauth/google/callback` URI.
An internal endpoint can be reached by the user's browser over VPN; it does not
require exposing the hub to Google's inbound network. Leave `IDP_CLIENT_ID` and
`IDP_CLIENT_SECRET` empty while preparing the host; the demo identity provider is
not a production fallback. Finish a real company sign-in before claiming identity
acceptance. See [identity providers](identity-providers.md).

For a TLS proxy bound to a WireGuard address, order its service after the tunnel.
A separate proxy instance can have its own service, PID, logs and renewal hook.
Log method/path/status without OAuth query strings. Permit its port only on the
VPN interface, then check both private access and failure through public IPv4/IPv6.
Keep application, database and registration ports unpublished or on loopback.

The private source checkout `smart-data-engines-mcp-registry/` is ignored by Git
and Docker. `python scripts/check_private_boundaries.py` rejects public-index
tracking and missing exclusions; CI runs this guard. Deployment source bundles
must use an explicit public-file list and omit the private registry, `.env`, local
state, credentials and the private product specification. Ship registry data through
a separate private channel, never through a public hub image or source archive.
