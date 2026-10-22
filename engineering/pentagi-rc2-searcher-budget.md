# PentAGI RC2 Searcher Budget Validation

Date: 2026-10-22

## Source and artifacts

- Branch: `exp/pentagi-integrated-rc2`
- Parent: `503bc3ee8462ab186bd9ea7b67e45ae41f30cbaf`
- Searcher budget code: `83cbc2520847d1ca0c6ee377cca8419f0d7c06c0`
- Pentester policy-rejection guidance: `63c113df4ef74416f3402a770fc76abdbf13ee04`
- Final image: `pentagi-local:2.2.0-opt-20261022-integrated-rc2`
- Image ID: `sha256:2173b8ed19b47057b0a311a092cc6c3bb0dcdd431d38b1b323e394edef3342ce`
- Binary SHA-256: `6015077cb159081b42e19e96a5447d71b3217f02aae2d396ab4dc1829c60fe23`
- Runtime used the Searcher-budget commit before the follow-up prompt addition. The final image includes both commits; the prompt addition has source-test verification only.

## Root cause and correction

`performAgentChain` used the general chain limit for Searcher. Repeated research
could consume the task budget before Primary returned to unfinished security
checks. RC2 adds configurable `MAX_SEARCHER_AGENT_ITERATIONS` (default `12`)
and applies it only to Searcher chains. Existing Primary and Pentester limits
remain unchanged. Searcher results still return through `search_result` to the
calling agent; unfinished Pentester work remains eligible afterward.

The A3 run also showed Pentester treating terminal policy rejections as a reason
to retry through other command forms. A narrow prompt rule now treats `BLOCKED:`
as an unexecuted request and forbids alternate-executable or shell bypasses. Its
rendered-prompt regression passes; behavioral impact remains untested.

## Matched runtime comparison

Both runs used the existing isolated A3 environment, authorized REST/BOLA
fixture, filtered `local-qwen-9b` route, and same fixed budget: 300,000 input
tokens, 80 target-call attempts, and 900 seconds. Qwen passed 300 seconds of
passive idle sampling (61 samples; four slots idle; zero observed generations
or queued requests).

| Measure | RC1 | RC2 |
|---|---:|---:|
| Accepted inference requests | 49 | 62 |
| Proxy input tokens | 292,505 | 291,926 |
| Searcher chains / input tokens | 2 / 248,659 | 3 / 102,069 |
| Searcher output tokens | 31,636 | 11,184 |
| Pentester chains / input tokens | 1 / 7,806 | 2 / 90,352 |
| Primary chains / input tokens | 1 / 8,579 | 3 / 24,988 |
| Selected terminal calls / blocked by guard | 1 / 1 | 9 / 5 |

Searcher input fell by 146,590 tokens (59%). In RC2 it used 35% of the captured
input budget; Pentester received 90,352 input tokens and Primary made three
chains. Primary persisted seven distinct subtasks. It delegated Pentester
twice. Searcher made three bounded delegations and returned three results.
Each run then refused its next request at the fixed input budget boundary.

## Security workflow result

No real HTTP request executed. The five rejected Pentester commands were:

1. Twice: `curl -s -D - -X POST http://pentagi-effectiveness-target:8000/api/auth/login ...`
   Rejected as `curl_option_not_allowlisted` (`-D` is not permitted).
2. `curl -s -X POST http://pentagi-effectiveness-target:8000/api/auth/login ...`
   Rejected as `only_read_requests_and_session_login_allowed`; the scoped
   fixture permits login only at its documented session endpoint.
3. A `curl` request using `$(cat /tmp/alice_token.txt)` and an authorization
   header. Rejected as `unsupported_shell_construct`.
4. A Python 3 `urllib` POST to `/api/auth/login`. Rejected as
   `shell_interpreter_not_allowed_in_bounded_benchmark`.

The guard was not changed. Its four persisted terminal executions returned the
guard's `BLOCKED` message; termlogs contain no API path, HTTP status, or invoice
response. The RC2 proxy ended at 291,926 tokens and refused a 9,213-token next
prompt. The budget watcher stopped flow 5 successfully. The flow and task are
`waiting`; Bob authentication is waiting, four security/reporting subtasks
remain created, and the Alice-authentication subtask was marked finished without
HTTP evidence. No verified BOLA, `hack_result`, `report_result`, or final task
report was produced. The fixture oracle's prior bilateral BOLA result remains
independent and was not supplied to the model.

## Verification and decision

Passed on the final source:

```text
go test -mod=readonly -p 2 ./pkg/providers ./pkg/tools ./pkg/controller ./pkg/config ./pkg/templates -count=1
```

All five packages passed using the pinned Go 1.26.5 builder. The focused
Searcher tests and prompt-rendering regression passed. `git diff --check`
passed. The image was rebuilt from the final commit on the integrated RC2 base.

**Searcher budget: KEEP EXPERIMENTAL.** Runtime evidence shows substantially
less Searcher input and more Pentester execution than RC1, but no vulnerability
discovery improvement is established. **End-to-end finding/report result:
INCOMPLETE.** Earliest remaining blocker is Pentester selecting a disallowed,
incorrect login route and failing to recover within the remaining model budget.
The new rejection guidance is not behaviorally validated. Production remains
unchanged.

Private raw captures and database evidence remain under the mode-0700 RC2 run
directory in the local optimization workspace; they are not part of this public
engineering record.
