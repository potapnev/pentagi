# API discovery execution guard

Automatic API discovery executes before the model response filter. At e2e6ad68,
its model-derived delegation URL could therefore reach the terminal without the
benchmark authorization decision. The earlier harness DNS attempt exposed a
boundary shared by the normal performer; it was not solely a harness defect.
No unauthorized egress probe was repeated.

Discovery now requires an operator-configured loopback HTTP policy endpoint in
`PENTAGI_API_DISCOVERY_GUARD_URL`. Before each terminal call, it POSTs the exact
TerminalAction JSON. A successful policy response must be HTTP 200 and contain
`allowed: true` plus `command_sha256`, the lowercase SHA-256 of the exact input
command. Missing configuration, denial, transport errors, redirects, malformed
or oversized responses, and mismatched hashes stop discovery before execution.
Proxy environment variables and redirects are disabled for policy requests.

The existing experimental filtered inference proxy can host this policy using
the saved scanner guard; no unrestricted inference route is needed. This is
an execution prerequisite for automatic discovery, not a general terminal
sandbox. Model-selected actions still require the existing response guard.
Deployments without an execution policy skip automatic discovery explicitly.

Regression first failed in all six denial cases because the executor was called.
After the fix, the provider/tools/controller/config/templates suite passes in
the pinned Go 1.26.5 builder. Tests use local HTTP policy mocks and recording
executors; no external request is executed.
