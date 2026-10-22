# PentAGI integrated RC1 engineering record

Date: 2026-10-22
Branch: `exp/pentagi-integrated-rc1`
Base: `b611fbebcf55b6deb88ad1fb7bf1f1ce7a357242`

## Integrated corrections

This branch combines four isolated, deterministic corrections:

| Commit | Change |
|---|---|
| `13f68fe` | Preserve generated assessment phases instead of collapsing them. |
| `ab3aeae` | Preserve request arguments alongside terminal evidence for Refiner. |
| `f5eddf8` | Correct terminal parsing of output redirection such as `2>&1`. |
| `295db7a` | Redact credentials from Searcher and research-only Memorist context. |

The HTTP-observation prompt candidate (`987d4c1`) was excluded because matched model evaluations did not demonstrate reliable benefit. No unrelated experimental branches were merged.

## Build and source verification

- Pinned offline tests passed: `go test -mod=readonly -p 2 ./pkg/providers ./pkg/tools ./pkg/controller -count=1`.
- `git diff b611fbebcf55b6deb88ad1fb7bf1f1ce7a357242..HEAD --check` passed.
- Review confirmed phase persistence/scheduling, request-evidence association, redaction, and the existing `hack_result` → Primary → Reporter → TaskWorker interfaces. Deterministic tests do not prove model behavior.
- Built image: `pentagi-local:2.2.0-opt-20261022-integrated-rc1`.
- Image ID: `sha256:0faba4535558dde6eaab251dec1390545ebb238bdc7db2c71375025ae4fa9424`.
- Binary SHA-256: `4c4f681bd7de9b8153bf2dc346b17d09a0b47786a63fe1d85246f14e3f8c9fbf`.
- Builder: `golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd`.
- Base: `vxcontrol/pentagi@sha256:64bd1802799142a12bc5eb23c15a1ccc50d3476736d3d2a98a9b773910283a1e`.

## Functional test

One fixed-budget A3 run used the saved disposable application, fixture, database, worker boundary, and filtered local Qwen configuration. Qwen3.5-9B readiness was observed for 300 seconds before inference.

- Primary generated eight distinct phases; they remained represented in persisted scheduling state (one running, seven queued).
- The model spent most of the fixed 300,000-input-token budget in Searcher, then delegated to Pentester once.
- Pentester's selected terminal action was blocked by the existing authorized-target guard. The fixed budget then ended the chain.
- No authenticated HTTP request, invoice authorization check, Pentester-verified vulnerability, `hack_result`, `report_result`, or final report was produced in this RC run. The flow remained waiting.
- An earlier baseline A3 run independently established that the fixture contains bilateral BOLA, but PentAGI did not test invoice details and produced a false-negative report. Evaluator ground truth was not supplied to the model.
- A read-only review of captured calls found repeated Searcher content, but the existing duplicate-call detector suppressed repeats; no deterministic repeat-detector defect was established.

## Decision and safety

**Source corrections: KEEP EXPERIMENTAL. Functional release: NOT READY.** The RC demonstrates phase scheduling and passes focused source tests, but did not complete meaningful Pentester testing or the finding/report lifecycle. No discovery or reporting improvement is claimed.

Production remains on `pentagi-local:2.2.0-opt-20261016.8`, expected image ID `sha256:a5cd000155440c2d898e34f7d47557ff385ca7c5804437b38a5cb36a604d66e1`. Production, flow 87, databases, volumes, providers, and production networking were not changed. The experimental image was built locally and was not deployed.

Raw model and runtime captures remain in the private local experiment archive; they are intentionally not included in this repository because they may contain credential-bearing prompts or sensitive evidence. This record contains no credentials or session tokens.

## Next validation

Use an existing safe runtime to test a narrowly budgeted Primary → Pentester sequence that performs authorized HTTP checks, invokes the supported `hack_result` tool, and verifies the normal persisted report path. Do not promote this RC until that workflow completes accurately, including negative controls.
