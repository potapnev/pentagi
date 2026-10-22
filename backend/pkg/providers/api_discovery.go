package providers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"pentagi/pkg/tools"
)

var (
	httpURLPattern    = regexp.MustCompile(`https?://[^\s<>"'\x60]+`)
	apiHTTPStatusLine = regexp.MustCompile(`^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)`)
	terminalSGR       = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	exitCodeSuffix    = regexp.MustCompile(`\r?\n\[exit code: (\d+)\]$`)
	hrefPattern       = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	linkPattern       = regexp.MustCompile(`(?i)<([^>]+)>\s*;\s*rel\s*=\s*["']?([^;"'\s]+)`)
)

var apiDocWellKnownPaths = []string{
	"/.well-known/openapi.json",
	"/openapi.json",
	"/swagger.json",
	"/api-docs",
	"/v3/api-docs",
	"/swagger/v1/swagger.json",
}

type apiDocumentedRoute struct {
	Method string
	Path   string
}

// discoverAPIDocumentation performs bounded, read-only GETs through the same
// terminal executor Pentester uses. Every attempt is a normal terminal tool
// call, so the command and genuine output are persisted by the existing path.
func discoverAPIDocumentation(
	ctx context.Context,
	executor tools.ContextToolsExecutor,
	question string,
) string {
	root, ok := apiAssessmentRoot(question)
	if !ok {
		return ""
	}

	candidates := []string{root}
	seen := map[string]struct{}{root: {}}
	appendCandidate := func(candidate string) {
		candidate = sameOriginURL(root, candidate)
		if candidate == "" {
			return
		}
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
	}

	observations := make([]string, 0, len(candidates))
	for i := 0; i < len(candidates) && i < 10; i++ {
		requestURL := candidates[i]
		args, err := json.Marshal(tools.TerminalAction{
			Input:   "curl -sS -i " + requestURL,
			Timeout: 20,
			Message: "Read the authorized target's root or documented API-description location to discover its published API contract.",
		})
		if err != nil {
			break
		}
		// Discovery is application-generated, so a model-response filter cannot
		// authorize it. Require the operator's execution policy before Docker.
		if err := authorizeAPIDiscovery(ctx, args); err != nil {
			return "<api_documentation_discovery>API documentation discovery not authorized: " + err.Error() + "</api_documentation_discovery>"
		}
		callID := fmt.Sprintf("api-discovery-%d-%02d", time.Now().UnixNano(), i)
		output, err := executor.Execute(ctx, 0, callID, tools.TerminalToolName, tools.TerminalToolName, "", args)
		if err != nil {
			observations = append(observations, fmt.Sprintf("GET %s was not executed: %v", requestURL, err))
			continue
		}

		status, headers, body, executed := parseTerminalHTTPResponse(output)
		if !executed {
			observations = append(observations, fmt.Sprintf("GET %s did not produce an executed HTTP response", requestURL))
			continue
		}
		observations = append(observations, fmt.Sprintf("GET %s returned HTTP %d", requestURL, status))

		for _, linked := range apiDocumentationLinks(root, requestURL, headers, body) {
			appendCandidate(linked)
		}
		// A successful curl process does not imply a successful HTTP response.
		// Never promote API routes from 4xx/5xx response bodies.
		if status >= 200 && status < 300 {
			if routes, valid := parseOpenAPIJSON(body); valid {
				return formatAPIDiscoveryContext(requestURL, status, routes)
			}
		}
		if i == 0 {
			// Prefer links published by the target response. Conventional
			// specification locations are a bounded fallback when the root page
			// does not advertise its documentation.
			for _, path := range apiDocWellKnownPaths {
				appendCandidate(joinTargetPath(root, path))
			}
		}
	}

	return "<api_documentation_discovery>\n" +
		"No usable API specification was found in the authorized read-only discovery responses. " +
		"The normal assessment path remains available; do not assume undocumented routes or HTTP outcomes.\n" +
		strings.Join(observations, "\n") + "\n</api_documentation_discovery>"
}

func preparePentesterAPIDiscoveryContext(
	ctx context.Context,
	executor tools.ContextToolsExecutor,
	question, userPrompt string,
) (string, string) {
	discovery := discoverAPIDocumentation(ctx, executor, question+"\n"+userPrompt)
	if discovery == "" {
		return question, userPrompt
	}
	return question + "\n\n" + discovery, userPrompt + "\n\n" + discovery
}

func apiAssessmentRoot(question string) (string, bool) {
	lower := strings.ToLower(question)
	apiTask := strings.Contains(lower, "api") || strings.Contains(lower, "rest") ||
		strings.Contains(lower, "graphql") || strings.Contains(lower, "endpoint")
	if !apiTask {
		return "", false
	}
	for _, candidate := range httpURLPattern.FindAllString(question, -1) {
		candidate = strings.TrimRight(candidate, ".,;:!?)]}")
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") {
			continue
		}
		parsed.RawQuery = ""
		parsed.Fragment = ""
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/"
		parsed.RawPath = ""
		return parsed.String(), true
	}
	return "", false
}

func joinTargetPath(root, path string) string {
	base, err := url.Parse(root)
	if err != nil {
		return ""
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.String()
}

func sameOriginURL(root, candidate string) string {
	base, err := url.Parse(root)
	if err != nil {
		return ""
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(parsed)
	if resolved.Scheme != base.Scheme || !strings.EqualFold(resolved.Host, base.Host) || resolved.User != nil {
		return ""
	}
	resolved.Fragment = ""
	resolved.RawQuery = ""
	return resolved.String()
}

func parseTerminalHTTPResponse(output string) (int, string, string, bool) {
	if strings.Contains(output, "BLOCKED:") {
		return 0, "", "", false
	}
	exitMatch := exitCodeSuffix.FindStringSubmatchIndex(output)
	if len(exitMatch) != 4 || output[exitMatch[2]:exitMatch[3]] != "0" {
		return 0, "", "", false
	}
	output = terminalSGR.ReplaceAllString(output[:exitMatch[0]], "")
	// TerminalTool captures a PTY. Its line discipline can turn HTTP CRLF into
	// CRCRLF, while curl may style headers with SGR escapes when stdout is a TTY.
	// Normalize these presentation artifacts before parsing the HTTP boundary.
	output = strings.ReplaceAll(output, "\r\r\n", "\n")
	output = strings.ReplaceAll(output, "\r\n", "\n")
	lineEnd := strings.Index(output, "\n")
	if lineEnd < 0 {
		return 0, "", "", false
	}
	firstLine := strings.TrimRight(output[:lineEnd], "\r")
	match := apiHTTPStatusLine.FindStringSubmatch(firstLine)
	if len(match) != 2 {
		return 0, "", "", false
	}
	var status int
	if _, err := fmt.Sscanf(match[1], "%d", &status); err != nil {
		return 0, "", "", false
	}
	rest := output[lineEnd+1:]
	separator := strings.Index(rest, "\n\n")
	separatorLen := 2
	if strings.HasPrefix(rest, "\n") {
		separator = 0
		separatorLen = 1
	}
	if separator < 0 || separatorLen == 0 {
		return 0, "", "", false
	}
	return status, output[:lineEnd+1+separator], rest[separator+separatorLen:], true
}

func apiDocumentationLinks(root, responseURL, headers, body string) []string {
	links := make([]string, 0)
	for _, match := range linkPattern.FindAllStringSubmatch(headers, -1) {
		rel := strings.ToLower(match[2])
		if strings.Contains(rel, "service-desc") || strings.Contains(rel, "service-doc") {
			links = append(links, match[1])
		}
	}
	for _, match := range hrefPattern.FindAllStringSubmatch(body, -1) {
		link := match[1]
		lower := strings.ToLower(link)
		if strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") || strings.Contains(lower, "api-doc") {
			links = append(links, link)
		}
	}
	resolved := make([]string, 0, len(links))
	response, err := url.Parse(responseURL)
	if err != nil {
		return resolved
	}
	for _, link := range links {
		parsedLink, err := url.Parse(link)
		if err != nil {
			continue
		}
		candidate := response.ResolveReference(parsedLink).String()
		if same := sameOriginURL(root, candidate); same != "" {
			resolved = append(resolved, same)
		}
	}
	return resolved
}

func parseOpenAPIJSON(body string) ([]apiDocumentedRoute, bool) {
	var document struct {
		OpenAPI string                                `json:"openapi"`
		Swagger string                                `json:"swagger"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal([]byte(body), &document) != nil || (document.OpenAPI == "" && document.Swagger == "") || len(document.Paths) == 0 {
		return nil, false
	}
	methods := map[string]struct{}{
		"get": {}, "head": {}, "post": {}, "put": {}, "patch": {}, "delete": {}, "options": {}, "trace": {},
	}
	routes := make([]apiDocumentedRoute, 0)
	for path, operations := range document.Paths {
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
			continue
		}
		for method := range operations {
			if _, ok := methods[strings.ToLower(method)]; ok {
				routes = append(routes, apiDocumentedRoute{Method: strings.ToUpper(method), Path: path})
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path == routes[j].Path {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Path < routes[j].Path
	})
	return routes, len(routes) > 0
}

func parseOpenAPIDocument(output string) ([]apiDocumentedRoute, int, bool) {
	status, _, body, executed := parseTerminalHTTPResponse(output)
	if !executed || status < 200 || status >= 300 {
		return nil, status, false
	}
	routes, ok := parseOpenAPIJSON(body)
	return routes, status, ok
}

func formatAPIDiscoveryContext(sourceURL string, status int, routes []apiDocumentedRoute) string {
	var b strings.Builder
	b.WriteString("<api_documentation_discovery>\n")
	b.WriteString("The following route inventory was parsed from a genuine HTTP response captured by the authorized terminal tool.\n")
	fmt.Fprintf(&b, "Documentation source: GET %s (HTTP %d).\n", sourceURL, status)
	b.WriteString("Documented operations:\n")
	for _, route := range routes {
		fmt.Fprintf(&b, "- %s %s\n", route.Method, route.Path)
	}
	b.WriteString("Treat prior route names without an executed, status-bearing target response or this documentation as unverified. Continue within the existing authorized scope.\n")
	b.WriteString("</api_documentation_discovery>")
	return b.String()
}

// authorizeAPIDiscovery fails closed without an explicit, command-bound decision.
// The endpoint is operator configuration, never derived from assessment content.
func authorizeAPIDiscovery(ctx context.Context, args json.RawMessage) error {
	endpoint, err := url.Parse(os.Getenv("PENTAGI_API_DISCOVERY_GUARD_URL"))
	if err != nil || endpoint.Scheme != "http" || (endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "::1") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("a loopback execution guard must be configured")
	}
	var action tools.TerminalAction
	if err := json.Unmarshal(args, &action); err != nil {
		return fmt.Errorf("invalid discovery action")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(args))
	if err != nil {
		return fmt.Errorf("invalid execution guard request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("execution guard unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("execution guard refused approval")
	}
	var decision struct {
		Allowed       bool   `json:"allowed"`
		CommandSHA256 string `json:"command_sha256"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &decision) != nil || !decision.Allowed || decision.CommandSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(action.Input))) {
		return fmt.Errorf("execution guard denied discovery command")
	}
	return nil
}
