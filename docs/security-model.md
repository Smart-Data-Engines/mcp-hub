# Security boundaries

| Input | Trust boundary |
|---|---|
| MCP arguments, HTTP headers and browser requests | Untrusted. Authentication, authorization, identity injection, schema checks and response redaction apply. |
| Controller deployment configuration | Supplied by the operator. Docker access, identity-provider settings, encryption keys and registry configuration require this authority. |
| Adapter code | Executes in an isolated worker. Review code before sharing tools or assigning a shared source-system account; adapters intentionally receive credentials. |

The registration helper reads `HUB_URL` from process configuration. Managed workers
receive a fixed registration-network endpoint from `Runtime.start`, after declared
Global Env values have been applied. Tool arguments and incoming HTTP requests do
not select that destination. Standalone adapters use an operator-configured Hub URL.

The development-only identity provider reads `DEMO_KEY_PATH` at process startup to
persist its local signing key. Compose supplies a path in the demo state mount;
HTTP requests never select that file. This provider does not authenticate users
and is bound to loopback in the reference Compose setup.

The optional operations scripts execute as the root deployment operator. They
load a fixed root-owned mode 0600 configuration file, containing trusted backup
paths and audit storage configuration. No HTTP route or tool argument supplies
those paths. They use argument lists, capture provider diagnostics and
coordinate maintenance through the deployment lock. A recovery checker gets an
isolated Redis address and read-only recovery files, without production networks
or the Docker socket. See [operations setup](operations-setup.md) for the separate
audit network and recovery-key custody.

CodeQL scans remote and local input sources. The environment-to-registration and
demo-key-file flows above are reviewed as trusted operator configuration, rather
than remotely supplied URLs or paths. This does not exclude their rules from
analysis. Revisit that assessment if a request, tool argument, personal credential
or unprivileged configuration source can ever select either value.
