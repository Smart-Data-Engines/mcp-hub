# Operations and recovery

## Diagnosis

- `/ready` is the traffic gate; `/health` includes catalog and upstream code versions.
- `/metrics` exposes traffic, decisions, credential sources, outbox loss, catalog,
  circuit state and Store memory. Application logs are redacted JSON on stdout.
- Correlate a tool's provenance `request_id` with its audit event and application log.
- A degraded upstream retains its last known tools. Open circuits fail fast while
  background reconciliation probes recovery; a request-budget timeout does not
  count as a session failure. Narrow an expensive query before increasing budgets.
- A code commit needs a console Restart. Check the running commit before debugging
  a suspected stale container. Dependency installation failures prevent execution.
- “Only personal credentials” errors require complete declared User Env fields.
  A decryption failure is not treated as an absent credential.
- Store memory above 80% of `maxmemory` produces a warning. With noeviction, capacity
  exhaustion denies new state writes; it does not evict permissions or credentials.

## Audit

Every tool call, including denials and replays, gets a new correlation ID and a
redacted audit event. Events are appended to the bounded Redis outbox; the external
sink is contacted by a worker, outside the tool's request path.

Set `AUDIT_SINK_URL` to an Elasticsearch/OpenSearch-compatible base URL and configure
credentials if needed. Events are PUT by correlation ID into `hub-audit-YYYY-MM-DD`.
Delivery is at least once with idempotent document IDs. Failed deliveries remain
buffered. Overflow or retention expiry increments a loss counter and logs a warning.
An unset sink leaves events in the outbox and warns; the outbox is not an unlimited
long-term audit archive. Configure retention/access policy at the external sink.

## Backup and restore

Keep the Redis 7 AOF directory, including its manifest and incremental/base files,
in the persistent state volume. Back up a consistent stopped-volume snapshot or
use the atomic namespace export during a maintenance window:

```sh
mcp-hub backup /secure/location/hub-state.json
```

The output is created with mode 0600 and contains native Redis DUMP payloads,
remaining TTLs and all state/indexes within the configured prefix. Treat it as
sensitive. Store the encryption keys separately; ciphertext is unrecoverable
without them. Outbox events and OAuth client registrations are included; access,
refresh, login and browser-session tokens are omitted, so users sign in again after
disaster recovery. Expiring non-session state keeps its original expiration age
instead of receiving a fresh lifetime when restored.

Stop all gateway replicas and restore into an **empty** namespace:

```sh
mcp-hub restore /secure/location/hub-state.json
```

Restore requires a Redis version compatible with the exported native payloads.
Verify group/admin counts, credentials indexes, definitions and audit outbox before
starting the controllers. A native Redis round-trip is part of container acceptance.
The export blocks the Redis primary while taking its atomic snapshot; schedule it
as maintenance. For large installations prefer storage-level consistent AOF backup.

## Key rotation

Set `CREDENTIALS_ENCRYPTION_KEY=new-key,old-key` on every replica. New writes use the
first key and reads accept either. Then run:

```sh
mcp-hub rotate-key
```

The command rotates encrypted credentials and Global Env using compare-and-set,
preserving concurrent updates and TTLs. Repeat if any writes raced the job. Verify
successful reads with only the new key before removing the old key from all replicas.

## Limits and trust

Configure the audit sink, provider tenant, source-system delegation and actual
network topology before company use. Source adapters intentionally receive callers'
credentials, so publishing shared code and assigning Global Env are trust decisions.
Redaction covers known injected/stored values, structured secret keys and bounded
patterns; it is not a general detector of arbitrary encodings or intentional data
exfiltration. Review shared adapters and pin deployment references where appropriate.

Access-token revocation is immediate at the Hub. It does not erase a source-system
side effect already accepted by an upstream. Writes with an uncertain timeout are
held by the idempotency window and require checking their outcome before retrying
after that window. Automatic replay of interrupted side effects is intentionally absent.
