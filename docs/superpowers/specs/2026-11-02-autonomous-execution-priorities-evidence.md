# Autonomous execution priorities: regression evidence

Date: 2026-11-02
Base: PentAGI 2.2.0, `b611fbeb` (no schema or version change)

## Production evidence and cause

Sanitized completed Flow 81 records 21 tasks and 35,238 tool calls. Its file-read history contains 44 calls across 19 exact signatures: 25 excess repeated calls; one signature ran 15 times. The regression fixture contains only aggregate counts and a redacted path.

The repetition detector was chain-local and consecutive-call-only. The planner/refiner could re-add completed subtasks, and completion trusted the reporter's success plus lifecycle status. Flow shutdown also marked unfinished work finished. Prompt prohibitions had no flow-wide enforcement.

## Changes

- Added a Flow-local normalized operation guard seeded from completed tool-call history. It suppresses repeated inspections, administrative terminal commands, reports, admin-only subtask changes, and identical delegations; it returns the previous result. New technical evidence permits a bounded follow-up, with a hard per-operation cap.
- Refiner receives technical/admin progress counts and bounded-discrepancy guidance. Completed admin subtasks are filtered unless later technical evidence justifies them. Refiner/delegate provider fallback failures stop retrying as malformed input.
- Added evidence-backed `COMPLETED`, `PARTIAL`, `BLOCKED`, and `FAILED` results. Assessment success requires every objective subtask to finish with recorded target-action response evidence. Only `COMPLETED` maps to the existing successful task/flow lifecycle status. Shutdown does not convert unfinished tasks into success.
- Preserved scope, authorization, safety, and non-destructive behavior. No migrations, infrastructure changes, or live target requests.

## Regression measurements

| Case | Before evidence | Fixed regression |
|---|---:|---:|
| Flow 81 most repeated file read | 15 executions | 1 execution, 14 blocked (93.3% fewer) |
| Flow 81 all file reads | 44 calls / 19 signatures / 25 excess repeats | Repeated signature is bounded; fixture replay verifies 1/15 |
| Conflicting request totals / repeated report | No cross-call bound | 1 report accepted, next same-task report blocked; 1/5 repeated reports accepted, 4 blocked |
| Same delegate after completion/restart | No persisted-history suppression | Seeded completed call blocks identical delegate replay |
| Reporter claims success with untested objective | Could finish successfully | Downgraded to `PARTIAL`; verified objective count remains 0 |
| Recreate completed admin task | Planner could re-add | Suppressed until later technical evidence; test verifies both paths |
| Distinct technical plan update | Could be confused with duplicate admin work | Allowed |

The Flow 81 fixture replay and isolated tests use synthetic arguments only. No live pentest was repeated.

## Verification

Passed, using the pinned Go 1.26.5 builder image:

```sh
go test -short -p 2 ./pkg/execution ./pkg/controller ./pkg/providers ./pkg/tools ./pkg/templates/... -count=1
```

Full backend suite was attempted:

```sh
go test -short -p 2 ./... -count=1 -timeout=3m
```

All affected packages passed. Unrelated installer/wizard tests failed because this source checkout does not contain the embedded deployment assets and `/opt/pentagi/conf` files those tests require (for example `backend/cmd/installer` `.env`, `files/fs/docker-compose.yml`, provider config fixtures). Other packages completed successfully. No unrelated assets were generated or changed.

`git diff --check` passed.

## Rollback

No DB migration or data mutation. Roll back code with `git revert <commit>` or rebuild the previous 2.2.0 revision `b611fbeb`. Existing PostgreSQL data and Flow history remain compatible.

## Deployment boundary

This branch is regression-validated and ready for review. The running PentAGI deployment was not restarted or upgraded during this change; active Flow 87 and its history remain untouched. Deploy only after that Flow is inactive, using this branch's image and preserving the existing PostgreSQL volume/configuration.
