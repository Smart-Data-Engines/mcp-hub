# Authoring a server

Create a server in the console. Its folder is `{owner-id}/{server-name}` in the
registry and contains `server.py`, `requirements.txt`, `manifest.yaml`, `env.yaml`
and `docker.yaml`. The hub commits multiple edited files as one Git change.

A retired server name remains reserved to its original owner. This prevents a
different author from taking over old name-based grants or saved credentials.

Use the generated scaffold and keep `serve(mcp)` from `mcp_hub.upstream`. It binds
port 3000, rejects missing/wrong upstream secrets, registers only after listening
and repeats registration with retry/backoff. Keep `mcp>=1.30,<2` in requirements.

An adapter using MCP SDK 2.x must pin its exact version, starting with `mcp==2.3.0`,
and pass its ASGI application to `mcp_hub.upstream.serve_app(app)`. This retains the
same secret guard, registration and heartbeat behavior without requiring the
gateway itself to use that SDK version. All tools still need the explicit hidden
`credentials` argument and annotations described below. Unbounded SDK 2.x ranges
and SDK 3.x are rejected by the runtime.

```python
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False))
async def lookup(query: str, credentials: dict | None = None) -> dict:
    caller = (credentials or {}).get("_hub_username")
    if not caller:
        raise ValueError("An authenticated caller is required")
    # Call the source system as this caller, or use their supplied credentials.
    return {"result": "example"}
```

Always declare `readOnlyHint` and `destructiveHint`. A mutating annotation without
an explicit non-destructive hint uses MCP's conservative destructive default.
Name-token heuristics apply only when annotations are absent and are visible in
coverage metrics. Shared adapters should have complete annotation coverage.

`credentials` is an explicit argument, never `**kwargs`. The client does not see
it in the advertised schema. The hub removes client-supplied identity/credential
arguments before injecting trusted `_hub_username`, `_hub_user_id` and
`_hub_principal`. Read identity from this dictionary, not from tool arguments or
untrusted request metadata. Validate identities before using them in HTTP headers.

Declare Global Env and User Env separately:

```yaml
env: [SERVICE_BASE_URL, SERVICE_API_KEY]
user_env: [user, password]
```

Only an administrator sets/reads Global Env values. Personal fields are saved under
the server's service name. Incomplete declared personal credentials are rejected;
they do not silently borrow missing fields from the technical account. A principal
without a source-system account must fail closed or use an explicit documented
service-account exception.

`both` chooses personal credentials with a global fallback when none exist.
`user_only` requires personal credentials. `global_only` ignores personal values;
a user's explicit “only mine” preference causes a clear refusal instead of a
silent account switch. Encryption/credential lookup failures are explicit errors.

Container resource limits are read from `docker.yaml`, clamped to 64–2048 MiB and
0.1–2 CPUs and checked against administrator-approved settings. Use the console
resource controls or an administrator's source edit to approve changes. Unreviewed
resource edits made directly in Git cannot raise the approved allocation.

Commit saves source; **Restart** deploys a fresh immutable registry snapshot. A
plain Docker restart uses the existing snapshot. Running commit IDs appear in the
console, `/health` and `hub.discover_tools`. Optional pinned tags/commits are honored.

The hub performs bounded argument-shape checks. Full tool JSON Schema validation
runs in the isolated upstream SDK; remote references and arbitrary schema regexes
are not executed in the privileged gateway. Upstream responses have both a wire
byte limit and a redacted content cap. Compressed upstream responses are rejected
to keep the transport limit effective before parsing/decompression.

Catalog pagination shares an aggregate byte/tool-count budget; splitting an
oversized catalog into pages does not bypass memory limits. The local source cache
keeps the current and previous snapshots per server. Older references remain in Git
and are fetched again when pinned/restarted; deleting a server removes its cache.
