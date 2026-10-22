# Filtered custom-provider bootstrap

The saved response filter allowed `get_number` globally but removed the legitimate
internal `submit_pattern` definition. The detector made five fruitless retries;
provider setup consumed the inference allowance before Pentester execution.

`LLM_SERVER_TOOL_CALL_ID_TEMPLATE` optionally supplies a custom-provider default.
The existing collector validates it against actual IDs before acceptance. An
incompatible value falls back to ordinary detection; an unset value preserves
existing behavior. The existing process cache remains unchanged. No format is
hard-coded for custom providers. The historical local endpoint emitted 15 IDs
matching `{r:32:x}`; the separately bounded live run validates this again.

`scripts/provider-bootstrap/` preserves the saved proxy and guard with a narrow
calibration contract. Both internal tools require an exact two-message setup
exchange, exact tool schema, and no additional tools or history. Dynamic portions
are limited to collector UUIDs and detector samples. Only the first detector
attempt is accepted; modified retry prompts fail closed. Responses accept only
the requested internal tool and its typed, bounded arguments. Ordinary
`submit_pattern` and `get_number` remain prohibited. Terminal command policy,
authentication prohibition, target restrictions, and discovery approval are
unchanged. No internal tool can authorize or execute a target operation.

The regression fixture contains only the two historical calibration requests and
responses, without credentials. The deterministic Go test runs the real custom
provider through the complete saved HTTP proxy against a local deterministic
peer, including token preflight, request filtering, response filtering and ledger
writes. It proves six generations without configuration, one for a compatible
default, seven after an incompatible default, and HTTP 409 for an ordinary
internal-tool attempt. Python regressions cover mixed tools, modified prompts,
schemas/history, response action smuggling, and ordinary terminal authorization.

Run from the repository root:

```sh
python3 -m unittest discover -s scripts/provider-bootstrap -v
cd backend
go test -mod=readonly ./pkg/providers/custom -run TestBootstrapFilteredCalibration -count=1 -v
```

The proxy fixes its generation cap at 10 and refuses to overwrite an existing
ledger. A fresh directory, input limit of 30,000, and explicit runtime limits are
required for the bounded runtime acceptance. Runtime evidence and deployment
configuration remain private in the lab assessment directory. Production, flow
87, previous ledgers, and historical branches are preserved.

## Bounded live acceptance

PASS on 2026-10-22, A3 flow 8/task 6/subtask 6. After a 300-second idle gate
(61 samples), the configured `{r:32:x}` template validated against three real
Qwen collector IDs in one generation: 594 input tokens (79 cached), 78 output.
Startup through calibration used three generations, 1,281 input and 87 output.
The complete run used eight generations, 19,078 input (415 cached), 921 output;
limits were 30,000 input, ten generations and one model terminal action.

Pentester was actually invoked and produced a response. Guarded automatic
`GET /` and `GET /openapi.json` returned HTTP 200. Pentester selected
`GET /api/v1/invoices`; the scoped guard allowed it and the genuine HTTP 401
response persisted as PostgreSQL tool-call 19, with fixture-log corroboration.
Terminal-log rows 26–31 cover all three requests. No authentication occurred.
The operator stopped flow 8 immediately; it is waiting. The enclosing Pentester
call is marked failed by cancellation; no final result/report is claimed.

The optional model-selected documentation GET was not obtained. The remaining
boundary is that the model selected a protected business route for an anonymous
operation. Further authentication or workflow assessment is outside this run.
The proxy is stopped and its ledger preserved. Historical ledgers and production
containers/worker 87 are unchanged. Codex cumulative telemetry was unavailable.

One launch correction happened before inference: rebuild the backend statically
with `CGO_ENABLED=0` for the Alpine runtime. No image rebuild, inference retry,
or budget reset occurred. The runtime binary was verified by SHA-256:
`1a32723fe47c129a4e4d39f44cc87bab5ca90b8e9ba8c25ee716007ad6759a8a`.
