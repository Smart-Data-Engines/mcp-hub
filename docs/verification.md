# Local reference verification

Updated 2026-10-18. Current publication checks include **179 passing non-Docker
tests**, including the actual TCP suite and nine Git publication-boundary cases.
The console has **15 passing browser workflows**, with an additional expanded
connection-mode layout regression at 320, 390, 768, 1024 and 1440 pixels. These
cover hidden-value preservation, explicit removal, failed-save recovery, real
server restart, optional source browsing and the basic-editor fallback.

The historical 2026-10-17 benchmark and artifact records below remain a separate
reference profile. Remote CI results are available in
[GitHub Actions](https://github.com/Smart-Data-Engines/mcp-hub/actions/workflows/ci.yml).

This is a functional/reference qualification of 0.1.0 on one Linux Docker host.
Company IdP accounts, a live company GitHub registry and a production audit sink
were not used. Site-specific acceptance remains required.

## Checks

| Check | Result |
|---|---|
| Python HTTP/unit/property/real-TCP suite | 179 passed; 3 Docker cases selected separately |
| Property invariants | 23 properties; 100 generated cases on open domains, exhaustive smaller domains |
| Native Docker/Redis suite | 3 passed: isolation, 128 MiB allocation, real effect counter, interactive approval, Git restart, two replicas, cutover/drain, failed dependency and native restore |
| Chrome console | 15 workflows passed; expanded connection modes also checked on desktop/tablet/mobile with mouse, keyboard and automated accessibility checks |
| Python lint/format | Ruff clean |
| Backend typing | mypy clean across 24 package modules |
| Console typing/build/format | TypeScript strict build, Vite production build and Prettier clean |
| Production npm audit | 0 vulnerabilities reported at verification time |
| Code/artifact consistency | Per-file source SHA-256 compared between workspace and installed image |
| Git exclusions | Local product specification, generated `.env`, caches, traces and screenshots ignored |

The Python-only coverage report is approximately 69% because Docker executes the
runtime/operator/installer code in the image and the browser exercises additional
management handlers. This is not presented as complete branch coverage. The security
properties, actual HTTP behavior and independent transport/container probes are the
acceptance evidence; a green count alone is not a readiness claim.

## Measurements

Profile: localhost, two read-only demonstration adapters, ten warmups, 200 sequential
`demo-directory.search` calls. Gateway overhead is measured from ASGI ingress to
response start with the upstream RPC span subtracted; it includes authentication,
permission reads, policy, redaction, durable audit append and response preparation.
Total client latency includes transport and upstream work and is shown separately.

| Metric | Before optimization | After optimization |
|---|---:|---:|
| Gateway p50 | 16.161 ms | 13.054 ms |
| Gateway p95 | 34.758 ms | 18.998 ms |
| Gateway p99 | 56.946 ms | **23.211 ms** |
| Total client p50 | 43.084 ms | 33.469 ms |
| Total client p95 | 86.453 ms | 41.719 ms |
| Total client p99 | 179.448 ms | 60.400 ms |
| Simultaneous HTTP connections returning ready=200 | 1000 | **1000** |

The measured gateway p99 meets the specification's <50 ms target in this profile.
The optimization consolidates response redaction before cap/provenance, avoids
re-redacting an already sanitized audit event, and coalesces concurrent readiness
probes for 250 ms. Token validation and ACL decisions are still uncached.

The native cutover test observes the signal timestamp inside the container and
concurrently polls readiness. One recorded transition was **10.841 ms** from SIGTERM
to HTTP 503; the final optimized-image run recorded **15.464 ms**. The accepted long call drained successfully and 20 calls continued
through the same test load-balancer URL after switching to the other controller.

Reproduce the local reference measurement with:

```sh
uv run python scripts/benchmark_demo.py
```

Detailed local results are in the ignored `.local/verification/benchmark.json` and
`benchmark-before.json`. Workload size, host load, proxy, TLS and source-system
behavior can materially change these numbers.

## Important failed attempts and corrections

- A full workstation filesystem caused the first image build to fail and a formatter
  to truncate new files. Twenty-one files were reconstructed from 24 recorded patch
  batches, checked with the AST parser, and all checks/images were rebuilt. The
  original local specification's SHA-256 remained unchanged.
- The first replica fixture incorrectly wrapped the Docker SDK endpoint mapping.
  The controller correctly refused to bind a control listener that did not resolve
  to its ingress address. The test mapping was corrected and the native two-controller
  path passed.
- Concurrent console/native tests used the same first-party OAuth client and
  invalidated each other's tokens under the intended login-deduplication policy.
  They are run sequentially and failed test adapters were removed.
- Timing from before the Docker kill HTTP call included Docker API latency; one
  such observation was 202 ms. The final oracle timestamps `os.kill(1, SIGTERM)` in
  the container and observes HTTP readiness concurrently. The 100 ms threshold was
  retained, not relaxed.
- The initial 1024 descriptor limit exhausted the controller under 1000 sockets:
  `EMFILE` appeared in logs; a diagnostic returned 45 HTTP 200 and 955 HTTP 503.
  The reference controller now explicitly uses soft/hard `nofile=65536`. Readiness
  probes are coalesced rather than opening a new Store connection for every probe.
- Initial gateway p99 was 56.946 ms. Redundant redaction passes were removed with
  regression coverage; the retained comparison above records both results.

## Original 2026-10-17 reference artifacts

Runtime: Python **3.13.16**, official MCP SDK **1.30.0**, Starlette **0.52.1**.
Host tests also executed on Python **3.14.4**. Dependencies are frozen in the lockfiles.

```text
mcp-hub:local
sha256:e21ee91b086a36484a0e08617244fa9e305292615080a4fcacae1d707af9ba9c

mcp-hub-upstream:local
sha256:361291328ef6a1de79bb374fbd5346ea4ed12ce4e8fcf03436edf93a13b7cafd

uv.lock
d328dce930b417c92012888d8dd537b706106694fa112236d03b7e7588031f43

frontend/package-lock.json
c0ffcc2ad2ff783ea6effa450b8469cba4b65e282693031a9e535fdf143ecb51

```

CI is configured with pinned action commits for Python 3.13/3.14, console checks and
native Docker/browser acceptance. The workflow has been mirrored locally; no remote
CI run is claimed before the code is committed/pushed.
