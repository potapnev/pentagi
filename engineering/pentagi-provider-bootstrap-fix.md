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
