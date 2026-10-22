# Pentester API Discovery Execution Correction

Date: 2026-10-22
Branch: `exp/pentagi-api-discovery-v1`
Base: `exp/pentagi-pentester-http-contract-v1` at `9c3a519de975477742c96d2c697b8761aa014d12`

## Root cause

The private A3 trace shows Primary first introduced the unsupported `/login` route in a `search` delegation. That question asked Searcher to probe guessed routes and report response statuses. Searcher has no terminal tool; it returned a text summary claiming successful HTTP responses without any target requests. The route claim then entered the Pentester task context. Before Pentester's first response, there was no status-bearing target request or genuine OpenAPI response in its conversation. Generic mentions of OpenAPI in the system prompt were not documentation evidence.

## Correction

- `performPentester` now runs a bounded API-documentation discovery step before the optional planner and before Pentester receives its task.
- Discovery uses only `curl -sS -i` GET requests through the existing Pentester terminal executor. The normal tool-call and terminal-log persistence paths record each command and returned output.
- It checks the task's target root, follows only same-origin documentation links from actual responses, then tries a short list of conventional OpenAPI specification locations if the root did not advertise one. It does not follow redirects.
- A route list is exposed to both the planner and Pentester only when the terminal output contains an actual HTTP status line, a successful process exit, a 2xx response, and a valid OpenAPI/Swagger document. Methods and paths are parsed from that document.
- `BLOCKED:` output, nonzero exits, missing status, error responses, and non-spec bodies cannot produce a route inventory. If no specification is found, the normal assessment path continues with an explicit unavailable result.
- The Search tool schema now distinguishes internet/memory research from live target requests and directs in-scope HTTP work to Pentester's terminal.

No fixture login path, account, resource identifier, or vulnerability conclusion is embedded in production code.

## Verification

Pinned builder: `golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd`.

Passed:

- `go test -mod=readonly -p 2 ./pkg/providers ./pkg/tools ./pkg/controller ./pkg/config ./pkg/templates -count=1`
- `git diff --check`
- Focused discovery regressions cover documented-link following, route parsing, delivery to planner/Pentester contexts, and rejection of blocked, missing-status, non-2xx, nonzero-exit, and `printf`-style non-HTTP output.

The full `docker build` attempt failed at link time with `no space left on device`. A static backend binary was then built from this branch with the pinned builder and Dockerfile's `CGO_ENABLED=0` setting. Local candidate image `pentagi-local:2.2.0-opt-20261022-api-discovery-v1` was made by replacing only the backend binary in the existing RC2 image; image ID: `sha256:2cdd4214849835b74d0302a02ad6cea0b8938810a908604fb6343aabc8169b6c`. Binary SHA-256: `94fc4f842d70366811e63550d408ae301afdca53bde993146651935569d403b8`.

The static binary launched from the image. Its network-disabled smoke invocation stopped at database DNS resolution, so this is a build/startup check, not an application runtime pass.

## Behavioral gates

- **Gate 1:** deterministic source tests pass. An earlier A3 preflight executed the same `curl -sS -i` form against the fixture's OpenAPI document and captured HTTP 200, but the new automatic discovery path has not yet been observed through the live guard and persisted application logs.
- **Gate 2:** not run. The saved A3 application uses its existing filtered Qwen endpoint at `127.0.0.1:18104`, which is unavailable. The underlying host Qwen endpoint reports `local-qwen-9b` and health 200, but no model request or five-minute readiness interval was attempted because bypassing the saved filter would change the experiment configuration.
- **Gate 3:** not run.

No fixture traffic was sent in this iteration; the previously exposed disposable fixture credential was not reused. Raw traces and credentials remain private and are not part of this branch.

Production image `.8`, flow 87, production data, volumes, and networks were not modified. The source correction remains experimental; model behavior and end-to-end findings are unverified.
