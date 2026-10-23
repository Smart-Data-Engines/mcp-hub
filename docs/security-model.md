# Security boundaries

| Input | Trust boundary |
|---|---|
| MCP arguments, HTTP headers and browser requests | Untrusted. Authentication, authorization, identity injection, schema checks and response redaction apply. |
| Controller deployment configuration | Supplied by the operator. Docker access, identity-provider settings, encryption keys and registry configuration require this authority. |
| Adapter code | Executes in an isolated worker. Review code before sharing tools or assigning a shared source-system account; adapters intentionally receive credentials. |

Tool names do not confer read permission. Missing annotations use the destructive default,
and stale catalogs are reinterpreted under that rule. Annotation claims do not make malicious
code read-only; source-system permissions and trust in the adapter author remain necessary.
The controller does not evaluate adapter-provided JSON Schema regex or references, including
the SDK's otherwise automatic output validation. Invalid catalog refreshes block new dispatch.

Approval and replay checks bind the actual resolved connection, policy, client and advertised
contract revision. Changing credentials cannot reuse an earlier approval or cached result.
Only an encrypted digest of this context is stored. This does not attest that external adapter
code behaves honestly or changes its advertised revision when its implementation changes.

Anonymous dynamic registration, personal credential storage, declarations and audit records
have explicit storage/complexity bounds. Audit entries above 8 KiB retain decision metadata,
`details_truncated` and a digest of the redacted original event. They do not retain the large
body. Logs with oversized messages or exception details are withheld without emitting partial
secret values. Operators still size Redis and Git storage and restrict public probe exposure
according to their deployment. Container networking is not a general egress allowlist; cloud
metadata/host services require host network policy when adapters are not trusted with them.

TLS trust uses the maintained certifi bundle, including when an explicit company CA is added.
Worker dependency installation uses that bundle unless the operator explicitly selects
`PIP_CERT`, and avoids implicitly reintroducing system roots. Rebuild both controller and worker
images for trust-store updates. `ADMIN_EMAILS` bindings are reconciled on subsequent successful
identity validation, including removal of a subject's old verified-email binding.

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
