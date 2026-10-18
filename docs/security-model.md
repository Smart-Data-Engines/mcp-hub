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

CodeQL scans remote and local input sources. The environment-to-registration and
demo-key-file flows above are reviewed as trusted operator configuration, rather
than remotely supplied URLs or paths. This does not exclude their rules from
analysis. Revisit that assessment if a request, tool argument, personal credential
or unprivileged configuration source can ever select either value.
