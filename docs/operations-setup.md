# Private operations stack

This optional stack adds OpenSearch audit storage, Prometheus, hourly encrypted
restic backups, daily isolated Redis recovery drills and weekly repository checks.
It is operator tooling for a single host, separate from the gateway lifecycle.

OpenSearch has no published ports and uses an internal Docker network shared only
with the controller. Its security plugin is disabled in this isolated topology.
Do not attach untrusted containers to that network or expose its HTTP endpoint.
For a remote or multi-tenant sink, use authenticated TLS instead. Prometheus and
the textfile collector listen on host loopback only. Keep every ingress private.

## Installation

1. Install `restic` and `age` from the host's signed distribution repository.
2. Create `/srv/mcp-hub/shared/operations` and `/etc/mcp-hub` with mode 0700.
   Create the operations `metrics` subdirectory with mode 0755. Create
   `/srv/mcp-hub/shared/audit-snapshots` owned by UID/GID 1000, mode 0700.
3. Install `deploy/operations.py` and `deploy/restore_check.py` into
   `/usr/local/lib/mcp-hub/`, root owned and mode 0644. Copy
   `operations.example.json` to `/etc/mcp-hub/operations.json`, root owned 0600.
   Adjust the gateway paths, private URLs and deployment lock. Pin `redis_image`
   to the exact running Redis image ID for native DUMP format compatibility.
4. Generate a strong repository password into `/etc/mcp-hub/restic-password`
   (root owned 0600). Choose the repository in `restic_environment`. S3-compatible
   stores use `s3:https://endpoint/bucket/prefix` plus `AWS_ACCESS_KEY_ID` and
   `AWS_SECRET_ACCESS_KEY`; SFTP uses a dedicated restricted SSH identity. Protect
   the JSON configuration because these credentials are secret. Initialize the
   selected repository once with `restic init` using that environment.
5. Copy `deploy/prometheus.yml`, `deploy/prometheus-rules.yml` and
   `deploy/compose.operations.yaml` into the operations directory. Keep the two
   Prometheus configuration files mode 0644; set the gateway scrape port to the
   real loopback mapping. Copy `operations.env.example` to `.env`, mode 0600.
   Start it with `docker compose --project-directory /srv/mcp-hub/shared/operations
   -f /srv/mcp-hub/shared/operations/compose.operations.yaml up -d`.
6. Configure an OpenSearch filesystem snapshot repository named `hub-backups`
   with location `/snapshots`, a `hub-audit-*` index template with one primary,
   zero replicas and `dynamic: false`, and an index retention policy. Keep only
   stable audit metadata indexed; the redacted original event remains in `_source`.
   On a single-node cluster also set `cluster.default_number_of_replicas` and
   `plugins.index_state_management.history.number_of_replicas` to zero. Set replica
   counts to zero on any bootstrap-created internal indexes. This profile has one
   copy of each shard; it relies on independently stored backups for disaster recovery.
7. Add `deploy/compose.audit-client.yaml` to the **gateway's** Compose invocation
   and set `AUDIT_SINK_URL=http://audit:9200` in its protected environment. Recreate
   only the gateway. Future deploys and rollback commands must keep this overlay.
   Confirm the existing outbox drains and the sink contains the events.
8. Run the `backup`, `drill`, `check` and `probe` tasks manually. Only then install
   the supplied systemd units and enable their timers. Read protected task status
   in the operations directory and validate the rules using `promtool`.

Never regard a repository on this same host as disaster protection. A local
repository is useful for initial verification; `HubBackupOffsiteMissing` remains
visible until a remote repository is configured. Test access from the actual
systemd service: filesystem sandboxing can hide SFTP identities under `/root`.
Keep dedicated operator identities under `/etc/mcp-hub/` instead.

## Recovery key and retention

The data backup excludes `CREDENTIALS_ENCRYPTION_KEY` from its environment copy.
Keep a separate owner-held recovery package with the full gateway environment,
restic password/configuration, registry deploy key and known hosts. Encrypt it
using `age` to an owner-controlled recovery identity, copy it off the host and
verify decryption without printing secrets. Keep the recipient's private identity
separate from both the backup repository and the server. Refresh this package on
key rotation or changes to OAuth, registry or backup credentials. Retain old
decryption keys for as long as backups encrypted with them are retained.

Backups contain native Redis state, the two generic deployment images, a release
manifest and a consistent native OpenSearch snapshot repository. The data backup
stores environment configuration with the credential encryption key removed.
OpenSearch snapshots keep seven days locally.
Restic keeps 24 hourly, 14 daily, 8 weekly and 6 monthly recovery points. Online
audit indexes should have an explicit retention policy; encrypted backup recovery
points may retain older events until their own retention expires. Configure an
append-only credential/object-lock policy at the remote store if supported.

The daily drill reads a snapshot **from restic**, starts a new internal Docker
network and disposable Redis, and compares permanent native DUMP payloads and TTLs.
It decrypts all recovered credential records using the separate live key. The
checker has no production network, Docker socket, registry, gateway or source
adapter. It does not start workers or call source-system APIs. Resources have
unique names and are removed in a `finally` block. Weekly checks read all encrypted
repository data before applying retention.

To recover the audit archive, restore the entire snapshot repository from one
restic recovery point, mount it **read only** into an isolated, compatible
OpenSearch instance, register a read-only filesystem repository, then restore the
selected native snapshot without global cluster state. Never copy a live search
engine data directory or modify its snapshot repository by hand.

## Monitoring and notifications

Prometheus checks gateway/upstream health, audit backlog and loss, backups and
recovery drills, repository checks, TLS expiry, disk capacity and probe freshness.
The probe is independent of the backup lock. `HubBackupOffsiteMissing` is an
intentional warning for an incomplete deployment. Other missing/stale metrics
must also be investigated; a successful systemd timer invocation alone is not
proof that a backup can be recovered.

Optionally proxy `/monitoring/` to `http://127.0.0.1:9098/monitoring/` at the existing
private ingress. The alerts page shows pending/firing rules. Outbound notifications
require an explicitly configured Alertmanager receiver and destination; this
template sends no email or chat messages. A same-host monitor cannot report a host
or VPN outage while that machine is down. Add an independent private-network probe
on a second host when one is available.

Keep scripts, configuration, alert rules and image versions under review. Repeat
an audit snapshot restore after search-engine upgrades, and update both the app
and worker images when runtime security dependencies change.
