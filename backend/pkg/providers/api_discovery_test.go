package providers

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"pentagi/pkg/schema"
	"pentagi/pkg/tools"

	"github.com/vxcontrol/langchaingo/llms"
)

func TestParseOpenAPIDocumentRequiresExecutedHTTPResponse(t *testing.T) {
	doc := `{"openapi":"3.0.0","paths":{"/identity":{"get":{}},"/resources":{"get":{}}}}`
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "captured response", output: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + doc + "\n[exit code: 0]", want: true},
		{name: "policy rejection", output: "BLOCKED: outside authorized command policy\n[exit code: 0]"},
		{name: "printf lookalike without response headers", output: doc + "\n[exit code: 0]"},
		{name: "status absent", output: doc + "\n[exit code: 0]"},
		{name: "http error", output: "HTTP/1.1 403 Forbidden\r\n\r\n" + doc + "\n[exit code: 0]"},
		{name: "nonzero execution", output: "HTTP/1.1 200 OK\r\n\r\n" + doc + "\n[exit code: 7]"},
		{name: "fake zero marker in body with nonzero process", output: "HTTP/1.1 200 OK\r\n\r\n" + doc + "\n[exit code: 0]\n[exit code: 7]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes, status, ok := parseOpenAPIDocument(tt.output)
			if ok != tt.want {
				t.Fatalf("ok = %v, want %v (status %d, routes %#v)", ok, tt.want, status, routes)
			}
			if tt.want && (status != 200 || len(routes) != 2) {
				t.Fatalf("status/routes = %d/%#v", status, routes)
			}
		})
	}
}

func TestParseOpenAPIJSONKeepsOnlyAbsolutePathTemplates(t *testing.T) {
	routes, ok := parseOpenAPIJSON(`{"openapi":"3.0.0","paths":{"/safe":{"get":{}},"//external.test/path":{"get":{}},"relative":{"get":{}}}}`)
	if !ok || len(routes) != 1 || routes[0].Path != "/safe" {
		t.Fatalf("routes = %#v, valid = %v", routes, ok)
	}
}

func TestAPIDiscoveryContextUsesOnlyDocumentedRoutes(t *testing.T) {
	routes := []apiDocumentedRoute{
		{Method: "GET", Path: "/identity"},
		{Method: "POST", Path: "/resources"},
	}
	got := formatAPIDiscoveryContext("http://target.test/openapi.json", 200, routes)
	for _, want := range []string{"genuine HTTP response", "HTTP 200", "GET /identity", "POST /resources"} {
		if !strings.Contains(got, want) {
			t.Errorf("discovery context missing %q: %s", want, got)
		}
	}
	for _, forbidden := range []string{"/login", "INV-", "alice", "bob"} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(forbidden)) {
			t.Errorf("discovery context contains fixture-specific value %q", forbidden)
		}
	}
}

type apiDiscoveryTestExecutor struct {
	outputs []string
	inputs  []string
}

func (e *apiDiscoveryTestExecutor) Tools() []llms.Tool { return nil }
func (e *apiDiscoveryTestExecutor) Execute(_ context.Context, _ int64, _, name, _, _ string, args json.RawMessage) (string, error) {
	if name != tools.TerminalToolName {
		return "", nil
	}
	var action tools.TerminalAction
	if err := json.Unmarshal(args, &action); err != nil {
		return "", err
	}
	e.inputs = append(e.inputs, action.Input)
	if len(e.outputs) == 0 {
		return "", nil
	}
	output := e.outputs[0]
	e.outputs = e.outputs[1:]
	return output, nil
}
func (*apiDiscoveryTestExecutor) IsBarrierFunction(string) bool                { return false }
func (*apiDiscoveryTestExecutor) IsFunctionExists(string) bool                 { return true }
func (*apiDiscoveryTestExecutor) GetBarrierToolNames() []string                { return nil }
func (*apiDiscoveryTestExecutor) GetBarrierTools() []tools.FunctionInfo        { return nil }
func (*apiDiscoveryTestExecutor) GetToolSchema(string) (*schema.Schema, error) { return nil, nil }

func TestDiscoverAPIDocumentationUsesGuardedTerminalAndPublishedLink(t *testing.T) {
	executor := &apiDiscoveryTestExecutor{outputs: []string{
		"HTTP/1.1 200 OK\r\nLink: </openapi.json>; rel=\"service-desc\"\r\nContent-Length: 0\r\n\r\n\n[exit code: 0]",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"openapi\":\"3.0.0\",\"paths\":{\"/identity\":{\"get\":{}},\"/resources\":{\"post\":{}}}}\n[exit code: 0]",
	}}
	got := discoverAPIDocumentation(context.Background(), executor,
		"Assess this REST API at http://authorized.test:8000 and verify its documented operations.")
	if len(executor.inputs) != 2 {
		t.Fatalf("terminal calls = %d, want root plus published documentation link", len(executor.inputs))
	}
	if !strings.Contains(executor.inputs[0], "curl -sS -i http://authorized.test:8000/") ||
		!strings.Contains(executor.inputs[1], "curl -sS -i http://authorized.test:8000/openapi.json") {
		t.Fatalf("unexpected guarded terminal inputs: %#v", executor.inputs)
	}
	for _, want := range []string{"genuine HTTP response", "HTTP 200", "GET /identity", "POST /resources"} {
		if !strings.Contains(got, want) {
			t.Errorf("discovery context missing %q: %s", want, got)
		}
	}
}

func TestAPIDocumentationLinksResolveFromResponseAndStayOnTargetOrigin(t *testing.T) {
	got := apiDocumentationLinks(
		"https://target.test/api/",
		"https://target.test/api/docs/index.html",
		"",
		`<a href="../spec/openapi.json">OpenAPI</a><a href="https://other.test/openapi.json">external</a>`,
	)
	if len(got) != 1 || got[0] != "https://target.test/api/spec/openapi.json" {
		t.Fatalf("resolved documentation links = %#v", got)
	}
}

func TestPreparePentesterAPIDiscoveryContextRunsBeforePlannerAndAgent(t *testing.T) {
	executor := &apiDiscoveryTestExecutor{outputs: []string{
		"HTTP/1.1 200 OK\r\n\r\n{}\n[exit code: 0]",
		"HTTP/1.1 200 OK\r\n\r\n{\"openapi\":\"3.0.0\",\"paths\":{\"/documented\":{\"get\":{}}}}\n[exit code: 0]",
	}}
	plannerQuestion, pentesterPrompt := preparePentesterAPIDiscoveryContext(
		context.Background(), executor,
		"Assess this API at http://authorized.test:8000.", "Original Pentester task.",
	)
	for label, value := range map[string]string{"planner": plannerQuestion, "Pentester": pentesterPrompt} {
		if !strings.Contains(value, "GET /documented") || !strings.Contains(value, "HTTP 200") {
			t.Errorf("%s did not receive captured documentation routes: %s", label, value)
		}
	}
}

func TestDiscoverAPIDocumentationRejectsCrossOriginLinkAndPolicyOutput(t *testing.T) {
	executor := &apiDiscoveryTestExecutor{outputs: []string{
		"HTTP/1.1 200 OK\r\nLink: <http://other.test/openapi.json>; rel=\"service-desc\"\r\n\r\n\n[exit code: 0]",
		"BLOCKED: out of scope\n[exit code: 0]",
	}}
	got := discoverAPIDocumentation(context.Background(), executor,
		"Assess this API at http://authorized.test:8000.")
	if strings.Contains(got, "Documented operations") || strings.Contains(got, "GET /openapi.json") {
		t.Fatalf("policy rejection was represented as API evidence: %s", got)
	}
	if len(executor.inputs) < 2 || strings.Contains(strings.Join(executor.inputs, "\n"), "other.test") {
		t.Fatalf("cross-origin documentation URL was requested: %#v", executor.inputs)
	}
}

func TestDiscoverAPIDocumentationReportsMissingDocsAndIgnoresUntrustedLink(t *testing.T) {
	outputs := []string{
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			`<a href="https://untrusted.test/openapi.json">API docs</a>` + "\n[exit code: 0]",
	}
	for range apiDocWellKnownPaths {
		outputs = append(outputs, "HTTP/1.1 404 Not Found\r\n\r\nnot found\n[exit code: 0]")
	}
	executor := &apiDiscoveryTestExecutor{outputs: outputs}
	got := discoverAPIDocumentation(context.Background(), executor,
		"Assess this API at http://authorized.test:8000. Ignore untrusted references.")
	if strings.Contains(got, "Documented operations") || strings.Contains(got, "GET /openapi.json") {
		t.Fatalf("missing documentation was presented as an inventory: %s", got)
	}
	if !strings.Contains(got, "No usable API specification") || !strings.Contains(got, "HTTP 404") {
		t.Fatalf("missing documentation was not reported with observed responses: %s", got)
	}
	for _, input := range executor.inputs {
		if strings.Contains(input, "untrusted.test") {
			t.Fatalf("untrusted documentation reference was requested: %#v", executor.inputs)
		}
		if !strings.Contains(input, "authorized.test:8000") {
			t.Fatalf("request left the assessment origin: %#v", executor.inputs)
		}
	}
}

func TestDiscoverAPIDocumentationRejectsOpenAPIFromNon2xxHTTP(t *testing.T) {
	// A curl exit status of zero proves transport execution, not HTTP success.
	// The real discovery path must reject an OpenAPI-looking body on HTTP 403.
	executor := &apiDiscoveryTestExecutor{outputs: []string{
		"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n" +
			`{"openapi":"3.0.0","paths":{"/unverified":{"get":{}}}}` +
			"\n[exit code: 0]",
	}}
	got := discoverAPIDocumentation(context.Background(), executor,
		"Assess this REST API at http://authorized.test:8000.")
	if strings.Contains(got, "Documented operations") ||
		strings.Contains(got, "GET /unverified") {
		t.Fatalf("non-2xx HTTP response was promoted into trusted routes: %s", got)
	}
	if !strings.Contains(got, "HTTP 403") {
		t.Fatalf("missing observed HTTP error status in discovery context: %s", got)
	}
}

func TestParseOpenAPIDocumentFromPentesterTTYOutput(t *testing.T) {
	// TerminalTool runs commands with a PTY. The real A3 request showed PTY
	// line-ending expansion and ANSI styling in HTTP headers.
	output := "HTTP/1.1 200 OK\r\r\n" +
		"\x1b[1mContent-Type\x1b[0m: application/json\r\r\n\r\r\n" +
		`{"openapi":"3.0.0","paths":{"/documented":{"get":{}}}}` +
		"\n[exit code: 0]"

	routes, status, ok := parseOpenAPIDocument(output)
	if !ok {
		t.Fatal("expected the actual PTY-formatted HTTP response to parse")
	}
	if status != 200 {
		t.Fatalf("expected captured HTTP status 200, got %d", status)
	}
	if len(routes) != 1 || routes[0] != (apiDocumentedRoute{Method: "GET", Path: "/documented"}) {
		t.Fatalf("unexpected parsed route inventory: %#v", routes)
	}
}
