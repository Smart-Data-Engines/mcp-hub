# Private audit storage and local recovery

This optional stack adds OpenSearch audit storage, hourly encrypted restic backups,
daily isolated Redis recovery drills and weekly repository checks. It runs
separately from the gateway lifecycle. It does not install a monitoring service,
alert rules or notification receivers.

OpenSearch has no published ports and uses an internal Docker network shared only
with the controller. Its security plugin is disabled in this isolated topology.
Do not attach untrusted containers to that network or expose its HTTP endpoint.
For a remote or multi-tenant sink, use authenticated TLS instead.

## Installation

1. Install `restic` and `age` from the host's signed distribution repository.
2. Create `/srv/mcp-hub/shared/operations` and `/etc/mcp-hub` with mode 0700.
   Create `/srv/mcp-hub/shared/audit-snapshots` owned by UID/GID 1000, mode 0700.
3. Install `deploy/operations.py` and `deploy/restore_check.py` into
   `/usr/local/lib/mcp-hub/`, root owned and mode 0644. Copy
   `operations.example.json` to `/etc/mcp-hub/operations.json`, root owned 0600.
   Adjust the gateway paths and deployment lock. Pin `redis_image` to the exact
   running Redis image ID for native DUMP format compatibility.
4. Generate a strong repository password into `/etc/mcp-hub/restic-password`
   (root owned 0600). Initialize the repository once with `restic init` using the
   environment from `restic_environment`. The example stores encrypted backups
   locally. Store the recovery password separately as described below.
5. Copy `deploy/compose.operations.yaml` into the operations directory. Copy
   `operations.env.example` to `.env`, mode 0600. Start the audit service with:

   ```sh
   docker compose --project-directory /srv/mcp-hub/shared/operations \
     -f /srv/mcp-hub/shared/operations/compose.operations.yaml up -d
   ```

6. Configure an OpenSearch filesystem snapshot repository named `hub-backups`
   with location `/snapshots`, a `hub-audit-*` index template with one primary,
   zero replicas and `dynamic: false`, and an index retention policy. Keep only
   stable audit metadata indexed; the redacted original event remains in `_source`.
   On a single-node cluster set `cluster.default_number_of_replicas` and
   `plugins.index_state_management.history.number_of_replicas` to zero. Set replica
   counts to zero on any bootstrap-created internal indexes. This profile has one
   copy of each shard.
7. Add `deploy/compose.audit-client.yaml` to the gateway's Compose invocation and
   set `AUDIT_SINK_URL=http://audit:9200` in its protected environment. Recreate
   only the gateway. Future deploys and rollback commands must keep this overlay.
   Confirm the existing outbox drains and the sink contains the events.
8. Run the `backup`, `drill` and `check` tasks manually. Only then install the six
   supplied systemd units and enable `mcp-hub-backup.timer`, `mcp-hub-drill.timer`
   and `mcp-hub-check.timer`. Inspect protected task status JSON files in the
   operations directory and use `systemctl status` / `journalctl` for failures.

Local backups recover accidental deletion and application failures while the
storage survives. Losing the host and its storage also loses those recovery
points. Rebuilding from source then requires configuring users, permissions and
server definitions again. An operator may choose this tradeoff for an internal
tool. The stack sends no automatic notifications.

If the recovery policy later requires off-host storage, restic also supports S3,
SFTP and other repositories. Configure credentials in the protected JSON file,
verify access from the actual systemd service and repeat recovery checks. Keep
SFTP operator identities under `/etc/mcp-hub/`; service sandboxing hides `/root`.

## Recovery keys and retention

The data backup excludes `CREDENTIALS_ENCRYPTION_KEY` from its environment copy.
Keep a separate owner-held recovery package with the full gateway environment,
restic password/configuration, registry deploy key and known hosts. Encrypt it
using `age` to an owner-controlled recovery identity and verify decryption without
printing secrets. Keep that private identity separate from both the repository
and the server. Refresh the recovery package on key rotation or changes to OAuth,
registry or backup credentials. Retain old decryption keys for as long as backups
encrypted with them are retained.

Backups contain native Redis state, the two generic deployment images, a release
manifest and a consistent native OpenSearch snapshot repository. The data backup
stores environment configuration with the credential encryption key removed.
OpenSearch snapshots keep seven days locally. Restic keeps 24 hourly, 14 daily,
8 weekly and 6 monthly recovery points. Online audit indexes should have an
explicit retention policy; encrypted backup recovery points may retain older
events until their own retention expires.

The daily drill reads a snapshot from restic, starts a new internal Docker network
and disposable Redis, and compares permanent native DUMP payloads and TTLs. It
checks decryption of recovered credential records with the separate live key.
The checker has no production network, Docker socket, registry, gateway or source
adapter. It does not start workers or call source-system APIs. Resources have
unique names and are removed in a finally block. Weekly checks read all encrypted
repository data before applying retention.

To recover the audit archive, restore the entire snapshot repository from one
restic recovery point, mount it read only into an isolated compatible OpenSearch
instance, register a read-only filesystem repository, then restore the selected
native snapshot without global cluster state. Never copy a live search-engine
data directory or modify its snapshot repository by hand. Repeat an audit snapshot
restore after search-engine upgrades. Update both the app and worker images when
runtime security dependencies change.
