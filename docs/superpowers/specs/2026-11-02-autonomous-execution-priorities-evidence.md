# Autonomous execution priorities: regression evidence

Date: 2026-11-02
Version: PentAGI 2.2.0; no schema change
Base: `65c50307b36bb85d356339793d200069111618e7`
Source commit: `69df0bfe`

## Cause

Flow 81 recorded 44 file reads across 19 exact signatures: 25 excess reads, with one signature executed 15 times. Signatures were task-scoped, so equivalent work in another Task or agent chain escaped the guard. Completed administrative subtasks could be re-added. Report reconciliation was treated as progress, and task/flow finish paths trusted report completion rather than technical evidence. Generic HTTP responses could satisfy the old coverage signal.

## Changes

- Canonicalize administrative file reads, filesystem commands, report reconciliation, report generation, and delegation identity across a Flow. Preserve authorization scope; invalidate cached file reads on writes; wait on concurrent equivalent work; reuse valid results; bound failed attempts and reopen after new technical evidence. Recovery seeds work state from persisted tool-call/task history.
- Filter completed administrative subtasks across a Flow until newer technical evidence justifies a follow-up. Refiner progress distinguishes technical evidence from administration; provider/delegation failures do not restart planning indefinitely.
- Map each mandatory objective to its non-administrative subtask and relevant target-action evidence. Track verified, negatively tested, inconclusive, untested, and blocked states. HTTP status alone, generic output, static markers, and reflected markers do not verify a vulnerability objective. A positive fixture result requires an objective-matched execution probe and a request marker returned as a specific execution witness. Reporting cannot satisfy technical objectives.
- Persist terminal `COMPLETED`, `PARTIAL`, `BLOCKED`, or `FAILED` in the existing task result; only evidence-backed `COMPLETED` maps to successful task/Flow lifecycle status. Unfinished work closed after worker loss is failed/incomplete, not successful.
- No database migration, production Flow mutation, or third-party request.

## Measured regression

| Scenario | Before | Fixed result |
|---|---:|---:|
| Flow 81 repeated file-read signature | 15 executions | 1 execution, 14 suppressed (93.3% fewer) |
| All Flow 81 file reads | 44 calls, 19 signatures, 25 excess | Replay fixture executes the 15-call signature once |
| Repeated report generation | No Flow-wide bound | 1/5 accepted; 4 suppressed |
| Same delegation after recovery | Prior history did not block cross-task replay | Completed persisted delegation is reused across Task IDs |
| 200 from WordPress REST with PHP-to-shell objective | Could qualify as success | `PARTIAL`; objective `untested` |
| Generic command output / static marker / reflected marker | Could qualify as success | `PARTIAL`; objective `inconclusive` |
| Known negative controlled fixture, matching probe and marker | No objective evidence gate | `COMPLETED`; objective `negatively_tested` |
| Known positive controlled fixture, matching probe and marker | No objective evidence gate | `COMPLETED`; objective `verified` |
| Untested mandatory objective plus finished report | Could be successful | `PARTIAL`; not `COMPLETED` |

Flow 81 replay uses its sanitized aggregate fixture and a redacted file path. The local HTTP fixture has known REST, reflected-marker, negative, and positive responses; no external target was contacted.

## Verification

Using Go `1.26.5-bookworm` inside the Docker runner, from the repository root:

```sh
docker run --name pentagi-regression-packages-root \
  -v "$PWD:/src" -v /tmp/pentagi-gomod:/go/pkg/mod \
  -w /src/backend golang:1.26.5-bookworm \
  go test -short -p 2 ./pkg/execution ./pkg/controller ./pkg/providers ./pkg/tools ./pkg/templates/... -count=1 -timeout=3m
```

Passed all listed packages when the complete repository root was mounted into the Go container. An initial run mounting only `backend/` failed three provider fixture assertions because `README.md` and `examples/configs/*.provider.yml` were outside the mount; rerun with repository root passed.

Final execution guard and objective changes:

```sh
docker run --name pentagi-regression-execution-final5 \
  -v "$PWD:/src" -v /tmp/pentagi-gomod:/go/pkg/mod \
  -w /src/backend golang:1.26.5-bookworm go test ./pkg/execution -count=1
docker run --name pentagi-regression-race-final3 \
  -v "$PWD:/src" -v /tmp/pentagi-gomod:/go/pkg/mod \
  -w /src/backend golang:1.26.5-bookworm \
  go test -race ./pkg/execution -count=1 -timeout=3m
docker run --name pentagi-regression-race \
  -v "$PWD:/src" -v /tmp/pentagi-gomod:/go/pkg/mod \
  -w /src/backend golang:1.26.5-bookworm \
  go test -race ./pkg/providers -count=1 -timeout=3m
```

The affected package command passed before the final matcher tightening; `execution` and its race test were rerun and passed after that final edit. `providers` was unchanged by the final edit and its race test passed. `TestCompletedFlow81RepeatedInspectionReplayIsBounded`, `TestFlowGuardBoundsRepeatedReportingMeasurably`, cross-task/concurrent/recovery tests, generic-response near misses, and `TestLocalHTTPFixtureMapsResponsesToPHPToShellObjective` pass.

The broader backend suite was attempted once:

```sh
go test -short -p 2 ./... -count=1 -timeout=3m
```

It remains red only in unrelated installer/wizard fixture tests requiring omitted embedded installation assets and `/opt/pentagi/conf` files. Those assets were not generated or changed. The affected package set above passes.

`git diff --check` passed. A first isolated image identity probe exposed a dynamically linked build; the binary was rebuilt with the Dockerfile's `CGO_ENABLED=0` setting before runtime verification.

## Isolated runtime

Image: `pentagi:2.2.0-execution-priorities-69df0bfe`
Image ID: `sha256:dc24dd4c95c32e3849b3e015d013fe76c3c00aa828567e3181d0e800f534e867`
Label and binary: `2.2.0-ce.h69df0bfe`

Built by compiling the changed backend with the pinned Go 1.26.5 builder and layering that binary onto the existing PentAGI 2.2.0 runtime image; frontend, configurations, and runtime base are unchanged. Ran against a fresh, isolated PostgreSQL/pgvector container and a test-only Docker network. `/api/v1/info` returned HTTP 200 and reported `2.2.0-ce.h69df0bfe`. The database had zero Flows. The local HTTP objective fixture test passed against the modified source.

## Production state and deployment

Before deployment, the database showed no `running` Flows. Flow 87 is `waiting`, which the operator confirmed is inactive. Its `pentagi-terminal-87` container remained present with the same container ID through deployment. PostgreSQL container/volume and configuration binds were preserved.

Previous app image ID: `sha256:64bd1802799142a12bc5eb23c15a1ccc50d3476736d3d2a98a9b773910283a1e` (`vxcontrol/pentagi:2.2.0`).

The deployment compose file hard-codes its image. A temporary override changed only that field; repository deployment files were not edited. Command, from `/home/master/workspaces/pentagi-lab`:

```sh
cat > /tmp/pentagi-image-override.yml <<'YAML'
services:
  pentagi:
    image: pentagi:2.2.0-execution-priorities-69df0bfe
YAML

docker compose \
  -f docker-compose.yml \
  -f docker-compose.cloud-free-max.override.yml \
  -f /tmp/pentagi-image-override.yml \
  up -d --no-deps --force-recreate pentagi
```

Rollback command:

```sh
docker compose \
  -f docker-compose.yml \
  -f docker-compose.cloud-free-max.override.yml \
  up -d --no-deps --force-recreate pentagi
```

No schema change. Production deployment completed. App container `0da7182f5001c01ef5068ea1ab1c51e41fd1ee74b56a6d45760c86c11d0e5742` runs image `sha256:dc24dd4c95c32e3849b3e015d013fe76c3c00aa828567e3181d0e800f534e867`, config image `pentagi:2.2.0-execution-priorities-69df0bfe`; startup log reports `2.2.0-ce.h69df0bfe`. `/api/v1/info` returned HTTP 200. Flow 87 remains `waiting`; its worker container ID is unchanged. PostgreSQL container `fc3b51b3fe44a3f4a220e17832bc1c6d3805050bb7a5fc61f649da2422190f01` and volume `pentagi-lab_pentagi-postgres-data` remain unchanged. No Flow had `running` status after deployment.

Exactly one successful production fixture request was made from the PentAGI container to a temporary static fixture on the local Docker network. It returned `pentagi-controlled-fixture-ok`; the fixture was stopped and removed. The smoke test did not create a Flow or contact a public/customer target. Source regression tests provide the execution-loop, objective, and fallback verification.

## Remaining limits

The isolated and production runtime checks do not launch a new autonomous assessment. The regression suite exercises objective mapping against synthetic known-positive/negative HTTP fixtures; remote response provenance cannot be cryptographically established by this change. A customer response that deliberately imitates the specific objective probe/witness remains an evidence-validation limit. Production provider/model fallback is exercised by provider tests, not by the no-Flow smoke request.
