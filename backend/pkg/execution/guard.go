package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/tools"
)

type AssessmentStatus string

const (
	OutcomeCompleted AssessmentStatus = "COMPLETED"
	OutcomePartial   AssessmentStatus = "PARTIAL"
	OutcomeBlocked   AssessmentStatus = "BLOCKED"
	OutcomeFailed    AssessmentStatus = "FAILED"
)

const defaultWorkDirectory = "/work"

type Coverage struct {
	Status           AssessmentStatus
	Objectives       int
	Verified         int
	ObjectiveResults []ObjectiveAssessment
}

type ObjectiveKind string

const (
	ObjectiveReconnaissance       ObjectiveKind = "reconnaissance"
	ObjectiveSurfaceDiscovery     ObjectiveKind = "surface_discovery"
	ObjectiveVulnerabilityTesting ObjectiveKind = "vulnerability_hypothesis_testing"
	ObjectiveExploitability       ObjectiveKind = "exploitability_validation"
	ObjectiveReporting            ObjectiveKind = "reporting"
)

type ObjectiveStatus string

const (
	ObjectiveVerified         ObjectiveStatus = "verified"
	ObjectiveNegativelyTested ObjectiveStatus = "negatively_tested"
	ObjectiveInconclusive     ObjectiveStatus = "inconclusive"
	ObjectiveUntested         ObjectiveStatus = "untested"
	ObjectiveBlocked          ObjectiveStatus = "blocked"
)

type ObjectiveAssessment struct {
	Objective   string          `json:"objective"`
	Kind        ObjectiveKind   `json:"kind"`
	Status      ObjectiveStatus `json:"status"`
	SubtaskID   int64           `json:"subtask_id,omitempty"`
	EvidenceIDs []int64         `json:"evidence_ids,omitempty"`
}

type workEntry struct {
	count        int
	attempts     int
	evidenceAt   int
	previousText string
	inFlight     chan struct{}
	waiters      int
}

// FlowGuard shares repeat history across agent chains and subtasks belonging to one Flow.
type FlowGuard struct {
	mu        sync.Mutex
	seen      map[string]workEntry
	fileState map[string]uint64
	taskScope map[int64]string
	evidence  int
	adminOps  int
	blocked   int
}

func NewFlowGuard() *FlowGuard {
	return &FlowGuard{seen: make(map[string]workEntry), fileState: make(map[string]uint64), taskScope: make(map[int64]string)}
}

// SetTaskScope records only authorization-relevant target and safety terms.
// It prevents result reuse when two Tasks in one Flow have different bounds.
func (g *FlowGuard) SetTaskScope(taskID int64, input string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.taskScope[taskID] = authorizationScope(input)
}

func (g *FlowGuard) HasTaskScope(taskID int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.taskScope[taskID]
	return ok
}

var targetScopeRE = regexp.MustCompile(`(?i)(https?://[^\s,;]+|(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})`)
var authorizationScopeRE = regexp.MustCompile(`(?i)(authorized|in.scope|scope|allowed|prohibited|exclude|read.only|non.destructive|rate.limit|testing window)[^.;\n]*`)

func authorizationScope(input string) string {
	values := append(targetScopeRE.FindAllString(input, -1), authorizationScopeRE.FindAllString(input, -1)...)
	for i := range values {
		values[i] = semanticText(values[i])
	}
	sort.Strings(values)
	return strings.Join(slices.Compact(values), "|")
}

// WorkPermit reserves one semantic operation before invoking the executor. A
// concurrent equivalent call waits for this permit and then reuses its result.
type WorkPermit struct {
	guard  *FlowGuard
	key    string
	name   string
	args   json.RawMessage
	taskID int64
	done   bool
}

func (p *WorkPermit) Complete(result string, succeeded bool) {
	if p == nil || p.guard == nil || p.done {
		return
	}
	p.done = true
	p.guard.mu.Lock()
	defer p.guard.mu.Unlock()
	entry := p.guard.seen[p.key]
	if succeeded {
		p.guard.recordLocked(p.name, p.args, result, true, p.taskID)
		entry.count++
		entry.attempts = 0
		entry.evidenceAt = p.guard.evidence
		entry.previousText = result
	} else {
		entry.attempts++
		entry.evidenceAt = p.guard.evidence
		entry.previousText = "Previous execution attempt failed. Retry only with a changed method or new evidence."
	}
	if entry.inFlight != nil {
		close(entry.inFlight)
		entry.inFlight = nil
	}
	p.guard.seen[p.key] = entry
}

// Acquire prevents concurrent duplicates and suppresses completed equivalent
// work until new technical evidence changes the Flow's evidence generation.
func (g *FlowGuard) Acquire(ctx context.Context, name string, args json.RawMessage, taskID int64) (*WorkPermit, string, bool, error) {
	for {
		g.mu.Lock()
		key, ok := g.signatureLocked(name, args, taskID)
		if !ok {
			g.mu.Unlock()
			return nil, "", true, nil
		}
		entry := g.seen[key]
		if entry.inFlight != nil {
			wait := entry.inFlight
			entry.waiters++
			g.seen[key] = entry
			g.mu.Unlock()
			select {
			case <-wait:
				g.mu.Lock()
				entry := g.seen[key]
				entry.waiters--
				g.seen[key] = entry
				g.mu.Unlock()
				continue
			case <-ctx.Done():
				g.mu.Lock()
				entry := g.seen[key]
				entry.waiters--
				g.seen[key] = entry
				g.mu.Unlock()
				return nil, "", false, ctx.Err()
			}
		}
		if (entry.count > 0 || entry.attempts >= 2) && entry.evidenceAt == g.evidence {
			g.blocked++
			previous := entry.previousText
			g.mu.Unlock()
			return nil, previous, false, nil
		}
		entry.inFlight = make(chan struct{})
		g.seen[key] = entry
		g.mu.Unlock()
		return &WorkPermit{guard: g, key: key, name: name, args: append(json.RawMessage(nil), args...), taskID: taskID}, "", true, nil
	}
}

func (g *FlowGuard) Blocked(name string, args json.RawMessage, taskID int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	key, ok := g.signatureLocked(name, args, taskID)
	if !ok {
		return false
	}
	entry, exists := g.seen[key]
	blocked := exists && (entry.inFlight != nil || (entry.count > 0 && entry.evidenceAt == g.evidence))
	if blocked {
		g.blocked++
	}
	return blocked
}

func (g *FlowGuard) PreviousResult(name string, args json.RawMessage, taskID int64) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	key, ok := g.signatureLocked(name, args, taskID)
	if !ok {
		return ""
	}
	return g.seen[key].previousText
}

func (g *FlowGuard) Record(name string, args json.RawMessage, result string, succeeded bool, taskID int64) {
	if !succeeded {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	key, ok := g.signatureLocked(name, args, taskID)
	g.recordLocked(name, args, result, true, taskID)
	if ok {
		entry := g.seen[key]
		entry.count++
		entry.evidenceAt = g.evidence
		entry.previousText = result
		g.seen[key] = entry
	}
}

func (g *FlowGuard) recordLocked(name string, args json.RawMessage, result string, succeeded bool, taskID int64) {
	if !succeeded {
		return
	}
	if isTechnicalEvidence(name, args, result) {
		g.evidence++
	}
	var fields map[string]any
	if name == "file" && json.Unmarshal(args, &fields) == nil {
		if action, _ := fields["action"].(string); action == string(tools.WriteFile) || action == string(tools.EditFile) {
			if path, _ := fields["path"].(string); path != "" {
				g.fileState[filepath.Clean(path)]++
			}
		}
	}
	if name == "terminal" {
		var action tools.TerminalAction
		if json.Unmarshal(args, &action) == nil {
			for _, match := range changedFileRE.FindAllStringSubmatch(action.Input, -1) {
				path := filepath.Clean(match[1])
				if !filepath.IsAbs(path) {
					cwd := action.Cwd
					if cwd == "" {
						cwd = defaultWorkDirectory
					}
					path = filepath.Join(cwd, path)
				}
				g.fileState[path]++
			}
		}
	}
	if _, ok := g.signatureLocked(name, args, taskID); ok {
		g.adminOps++
	}
}

func (g *FlowGuard) Seed(calls []database.Toolcall) {
	for _, call := range calls {
		if call.Status == database.ToolcallStatusFinished {
			taskID := int64(0)
			if call.TaskID.Valid {
				taskID = call.TaskID.Int64
			}
			g.Record(call.Name, call.Args, call.Result, true, taskID)
		}
	}
}

func (g *FlowGuard) signatureLocked(name string, args json.RawMessage, taskID int64) (string, bool) {
	return workSignatureWithState(name, args, taskID, g.fileState, g.taskScope[taskID])
}

func (g *FlowGuard) TechnicalEvidenceCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.evidence
}

func (g *FlowGuard) Stats() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]int{"technical_evidence": g.evidence, "administrative_operations": g.adminOps, "duplicate_operations_blocked": g.blocked}
}

var toolCommandRE = regexp.MustCompile(`(?i)(^|[;&|\s])(?:sudo\s+)?(?:curl|wget|nmap|naabu|httpx|nuclei|ffuf|feroxbuster|gobuster|dirsearch|sqlmap)(?:\s|$)`)
var adminCommandRE = regexp.MustCompile(`(?i)(^|[;&|\s])(?:sudo\s+)?(?:ls|cat|find|grep|rg|stat|wc|head|tail|tree|pwd|du|sha256sum|jq)(?:\s|$)`)
var httpStatusRE = regexp.MustCompile(`(?i)HTTP/\d(?:\.\d)?\s+\d{3}`)
var requestCountRE = regexp.MustCompile(`\d+\s+requests?`)
var changedFileRE = regexp.MustCompile(`(?i)(?:>|\btee\s+|-o\s+)(?:'|")?([^'"\s;|]+)`)

func isTechnicalEvidence(name string, args json.RawMessage, result string) bool {
	if name == "pentester" {
		return hasDelegatedTechnicalEvidence(result)
	}
	if !isTargetAttempt(name, args) || !hasNonGenericResponse(result) || strings.Contains(strings.ToLower(result), "connection refused") || strings.Contains(strings.ToLower(result), "could not resolve host") {
		return false
	}
	return true
}

func hasDelegatedTechnicalEvidence(result string) bool {
	text := strings.ToLower(result)
	return httpStatusRE.MatchString(result) && hasNonGenericResponse(result) ||
		strings.Contains(text, "technical finding:") || strings.Contains(text, "vulnerability tested:") ||
		strings.Contains(text, "not vulnerable after") || strings.Contains(text, "target response evidence:")
}

func isTargetAttempt(name string, args json.RawMessage) bool {
	switch name {
	case "terminal":
		var action tools.TerminalAction
		return json.Unmarshal(args, &action) == nil && toolCommandRE.MatchString(action.Input)
	case "browser":
		var action tools.Browser
		return json.Unmarshal(args, &action) == nil && (strings.HasPrefix(action.Url, "http://") || strings.HasPrefix(action.Url, "https://"))
	default:
		return false
	}
}

func isDiscoveryEvidence(name string, args json.RawMessage, result string) bool {
	return isTargetAttempt(name, args) && (httpStatusRE.MatchString(result) || strings.Contains(strings.ToLower(result), "<html") || strings.Contains(strings.ToLower(result), "# ") || hasNonGenericResponse(result))
}

func hasNonGenericResponse(result string) bool {
	for _, line := range strings.Split(result, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || httpStatusRE.MatchString(line) {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "http/") {
			continue
		}
		return true
	}
	return false
}

func workSignature(name string, args json.RawMessage, taskID int64) (string, bool) {
	return workSignatureWithState(name, args, taskID, nil, "")
}

var catReadCommandRE = regexp.MustCompile(`(?i)^\s*cat\s+['"]?([^'"| >]+)['"]?\s*$`)

func workSignatureWithState(name string, args json.RawMessage, taskID int64, fileState map[string]uint64, authScope string) (string, bool) {
	var fields map[string]any
	if json.Unmarshal(args, &fields) != nil {
		return "", false
	}
	delete(fields, "message")
	semanticName := name
	keepTaskID := false
	switch name {
	case "file":
		if fields["action"] != string(tools.ReadFile) {
			return "", false
		}
		path, _ := fields["path"].(string)
		path = filepath.Clean(path)
		fields = map[string]any{"path": path, "revision": fileState[path]}
	case "terminal":
		var action tools.TerminalAction
		if json.Unmarshal(args, &action) != nil || toolCommandRE.MatchString(action.Input) {
			return "", false
		}
		if match := catReadCommandRE.FindStringSubmatch(action.Input); match != nil {
			semanticName = "file"
			path := filepath.Clean(match[1])
			if !filepath.IsAbs(path) {
				cwd := action.Cwd
				if cwd == "" {
					cwd = defaultWorkDirectory
				}
				path = filepath.Clean(filepath.Join(cwd, path))
			}
			fields = map[string]any{"path": path, "revision": fileState[path]}
			break
		}
		if !adminCommandRE.MatchString(action.Input) || strings.ContainsAny(action.Input, ">|;&") {
			return "", false
		}
		fields = map[string]any{"input": strings.Join(strings.Fields(action.Input), " "), "cwd": action.Cwd}
	case "report_result":
		result, _ := fields["result"].(string)
		fields = map[string]any{"result": semanticText(result), "authorization_scope": authScope}
		if isRequestCountReconciliation(result) {
			fields = map[string]any{"result": "request-count-reconciliation", "authorization_scope": authScope}
		}
	case "subtask_list":
		fields = map[string]any{"operation": name}
		keepTaskID = true
	case "subtask_patch":
		var patch tools.SubtaskPatch
		if json.Unmarshal(args, &patch) == nil && len(patch.Operations) > 0 {
			adminOnly := true
			operations := make([]string, 0, len(patch.Operations))
			for _, operation := range patch.Operations {
				if (operation.Op != tools.SubtaskOpAdd && operation.Op != tools.SubtaskOpModify) || !IsAdministrativeWork(operation.Title, operation.Description) {
					adminOnly = false
					break
				}
				operations = append(operations, administrativeTaskKey(operation.Title, operation.Description))
			}
			if adminOnly {
				sort.Strings(operations)
				fields = map[string]any{"operation": operations}
			}
		}
	case "pentester", "coder", "maintenance":
		question, _ := fields["question"].(string)
		canonical := semanticText(question)
		if isEvidenceReconciliation(question) {
			canonical = "evidence-file-reconciliation"
		}
		if isRequestCountReconciliation(question) {
			canonical = "request-count-reconciliation"
		}
		fields = map[string]any{"question": canonical, "authorization_scope": authScope}
	default:
		return "", false
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(append([]byte(semanticName+":"), canonical...))
	if keepTaskID {
		return fmt.Sprintf("%s:%d:%s", semanticName, taskID, hex.EncodeToString(sum[:])), true
	}
	return fmt.Sprintf("%s:%s", semanticName, hex.EncodeToString(sum[:])), true
}

func semanticText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Join(strings.Fields(semanticPunctuationRE.ReplaceAllString(value, " ")), " ")
}

var semanticPunctuationRE = regexp.MustCompile(`[^a-z0-9:/._-]+`)

func isRequestCountReconciliation(value string) bool {
	text := strings.ToLower(value)
	return strings.Contains(text, "request") && (strings.Contains(text, "count") || strings.Contains(text, "total") || requestCountRE.MatchString(text)) &&
		(strings.Contains(text, "reconcil") || strings.Contains(text, "discrep") || strings.Contains(text, "conflict") || strings.Contains(text, "vs") || requestCountRE.MatchString(text))
}

func isEvidenceReconciliation(value string) bool {
	text := strings.ToLower(value)
	return strings.Contains(text, "evidence") && (strings.Contains(text, "file") || strings.Contains(text, "filesystem")) &&
		(strings.Contains(text, "reconcil") || strings.Contains(text, "inspect") || strings.Contains(text, "review") || strings.Contains(text, "read"))
}

func IsAdministrativeWork(title, description string) bool {
	text := strings.ToLower(title + " " + description)
	for _, marker := range []string{"reconcil", "request count", "evidence file", "filesystem", "manifest", "report", "documentation", "checkpoint", "inventory file"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func administrativeTaskKey(title, description string) string {
	text := strings.ToLower(strings.Join(strings.Fields(title+" "+description), " "))
	if strings.Contains(text, "request") && (strings.Contains(text, "count") || strings.Contains(text, "total")) && (strings.Contains(text, "reconcil") || strings.Contains(text, "discrep") || strings.Contains(text, "conflict")) {
		return "request-count-reconciliation"
	}
	if strings.Contains(text, "evidence") && (strings.Contains(text, "file") || strings.Contains(text, "filesystem")) && (strings.Contains(text, "inspect") || strings.Contains(text, "read") || strings.Contains(text, "review")) {
		return "evidence-file-inspection"
	}
	return strings.Join(strings.Fields(strings.Join(strings.Fields(title+" "+description), " ")), " ")
}

func HasCompletedAdministrativeMatch(plan []tools.SubtaskInfo, completed []database.Subtask) bool {
	keys := make(map[string]struct{})
	for _, prior := range completed {
		if prior.Status == database.SubtaskStatusFinished && IsAdministrativeWork(prior.Title, prior.Description) {
			keys[administrativeTaskKey(prior.Title, prior.Description)] = struct{}{}
		}
	}
	for _, candidate := range plan {
		if IsAdministrativeWork(candidate.Title, candidate.Description) {
			if _, ok := keys[administrativeTaskKey(candidate.Title, candidate.Description)]; ok {
				return true
			}
		}
	}
	return false
}

func HasAdministrativeCandidate(plan []tools.SubtaskInfo) bool {
	for _, candidate := range plan {
		if IsAdministrativeWork(candidate.Title, candidate.Description) {
			return true
		}
	}
	return false
}

// FilterRepeatedAdministrativeWork drops a completed admin assignment unless later target evidence exists.
func FilterRepeatedAdministrativeWork(plan []tools.SubtaskInfo, completed []database.Subtask, calls []database.Toolcall) []tools.SubtaskInfo {
	type completedWork struct {
		taskID int64
		at     time.Time
		valid  bool
	}
	completedKeys := make(map[string]completedWork)
	for _, prior := range completed {
		if prior.Status != database.SubtaskStatusFinished || !IsAdministrativeWork(prior.Title, prior.Description) {
			continue
		}
		completedKeys[administrativeTaskKey(prior.Title, prior.Description)] = completedWork{
			taskID: prior.TaskID, at: prior.UpdatedAt.Time, valid: prior.UpdatedAt.Valid,
		}
	}
	out := make([]tools.SubtaskInfo, 0, len(plan))
	for _, candidate := range plan {
		if !IsAdministrativeWork(candidate.Title, candidate.Description) {
			out = append(out, candidate)
			continue
		}
		prior, found := completedKeys[administrativeTaskKey(candidate.Title, candidate.Description)]
		if !found {
			out = append(out, candidate)
			continue
		}
		newEvidence := false
		for _, call := range calls {
			if prior.valid && call.CreatedAt.Valid && call.CreatedAt.Time.After(prior.at) && call.Status == database.ToolcallStatusFinished && isTechnicalEvidence(call.Name, call.Args, call.Result) {
				newEvidence = true
				break
			}
		}
		if newEvidence {
			out = append(out, candidate)
		}
	}
	return out
}

func IsAssessmentTask(input string) bool {
	text := strings.ToLower(input)
	for _, marker := range []string{"penetration test", "pentest", "security assessment", "vulnerability assessment", "security test"} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return strings.Contains(text, "vulnerability") && (strings.Contains(text, "test") || strings.Contains(text, "hypothesis") || strings.Contains(text, "assess"))
}

var mandatoryObjectivePatterns = []struct {
	key string
	pat *regexp.Regexp
}{
	{"php-to-shell", regexp.MustCompile(`(?i)php[ -]to[ -]shell|php.{0,20}shell|shell.{0,20}php`)},
	{"remote-code-execution", regexp.MustCompile(`(?i)remote code execution|\brce\b`)},
	{"command-execution", regexp.MustCompile(`(?i)command execution|command injection|os command`)},
	{"file-upload", regexp.MustCompile(`(?i)file upload.{0,30}(vulnerab|execut|php)|(?:vulnerab|execut).{0,30}file upload`)},
	{"sql-injection", regexp.MustCompile(`(?i)sql injection|\bsqli\b`)},
	{"path-traversal", regexp.MustCompile(`(?i)path traversal|directory traversal`)},
}

func objectiveKind(text string) ObjectiveKind {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "exploitability") || strings.Contains(lower, "command execution") || strings.Contains(lower, "php-to-shell") || strings.Contains(lower, "rce"):
		return ObjectiveExploitability
	case strings.Contains(lower, "vulnerab") || strings.Contains(lower, "hypothesis") || strings.Contains(lower, "injection") || strings.Contains(lower, "traversal") || strings.Contains(lower, "upload"):
		return ObjectiveVulnerabilityTesting
	case strings.Contains(lower, "endpoint") || strings.Contains(lower, "api") || strings.Contains(lower, "surface") || strings.Contains(lower, "route"):
		return ObjectiveSurfaceDiscovery
	default:
		return ObjectiveReconnaissance
	}
}

func mandatoryObjectives(input string) []string {
	var objectives []string
	seen := make(map[string]struct{})
	for _, candidate := range mandatoryObjectivePatterns {
		if candidate.pat.MatchString(input) {
			if _, ok := seen[candidate.key]; !ok {
				objectives = append(objectives, candidate.key)
				seen[candidate.key] = struct{}{}
			}
		}
	}
	return objectives
}

func objectiveMatch(key, text string) bool {
	lower := strings.ToLower(text)
	switch key {
	case "php-to-shell":
		return strings.Contains(lower, "php-to-shell") || strings.Contains(lower, "php to shell") || strings.Contains(lower, "php shell")
	case "remote-code-execution":
		return strings.Contains(lower, "remote code execution") || strings.Contains(lower, "rce")
	case "command-execution":
		return strings.Contains(lower, "command execution") || strings.Contains(lower, "command injection") || strings.Contains(lower, "os command")
	case "file-upload":
		return strings.Contains(lower, "file upload") && (strings.Contains(lower, "vulnerab") || strings.Contains(lower, "execut") || strings.Contains(lower, "php"))
	case "sql-injection":
		return strings.Contains(lower, "sql injection") || strings.Contains(lower, "sqli")
	case "path-traversal":
		return strings.Contains(lower, "path traversal") || strings.Contains(lower, "directory traversal")
	default:
		return false
	}
}

func matchingEvidence(objective string, kind ObjectiveKind, subtask database.Subtask, calls []database.Toolcall) ObjectiveAssessment {
	result := ObjectiveAssessment{Objective: objective, Kind: kind, Status: ObjectiveUntested, SubtaskID: subtask.ID}
	for _, call := range calls {
		if !call.SubtaskID.Valid || call.SubtaskID.Int64 != subtask.ID || call.Status != database.ToolcallStatusFinished {
			continue
		}
		if !isTargetAttempt(call.Name, call.Args) {
			continue
		}
		args := strings.ToLower(string(call.Args))
		output := strings.ToLower(call.Result)
		if kind == ObjectiveReconnaissance || kind == ObjectiveSurfaceDiscovery {
			result.EvidenceIDs = append(result.EvidenceIDs, call.ID)
			if isDiscoveryEvidence(call.Name, call.Args, call.Result) {
				result.Status = ObjectiveVerified
			}
			continue
		}
		if !objectiveEvidenceMatches(objective, args) {
			continue
		}
		result.EvidenceIDs = append(result.EvidenceIDs, call.ID)
		if objectiveProofMatches(objective, args, output) {
			result.Status = ObjectiveVerified
			continue
		}
		if objectiveNegativeMatches(objective, args, output) {
			result.Status = ObjectiveNegativelyTested
			continue
		}
		if result.Status == ObjectiveUntested {
			result.Status = ObjectiveInconclusive
		}
	}
	if result.Status == ObjectiveInconclusive && len(result.EvidenceIDs) == 0 {
		result.Status = ObjectiveUntested
	}
	return result
}

func objectiveEvidenceMatches(objective, evidence string) bool {
	for _, key := range mandatoryObjectives(objective) {
		if objectiveMatch(key, evidence) {
			return true
		}
	}
	words := strings.Fields(semanticText(objective))
	matched := 0
	for _, word := range words {
		if len(word) >= 4 && !strings.Contains(" test assessment objective evaluate inspect check verify confirm against using with from that this ", " "+word+" ") && strings.Contains(semanticText(evidence), word) {
			matched++
		}
	}
	return matched >= 2
}

var objectiveProofRE = regexp.MustCompile(`(?i)(php execution marker|uploaded file executed|shell marker executed|test marker executed)`)
var objectiveNegativeRE = regexp.MustCompile(`(?i)(not executed|was rejected|not vulnerable|not reproduced|marker-not-executed|execution was blocked)`)
var requestMarkerRE = regexp.MustCompile(`(?i)[?&]marker=([a-z0-9_-]{4,})`)
var executionProbeRE = regexp.MustCompile(`(?i)(?:execution_probe|vulnerability_probe)=([a-z0-9_-]+)`)

func hasObjectiveExecutionProbe(objective, args string) bool {
	for _, match := range executionProbeRE.FindAllStringSubmatch(args, -1) {
		if objectiveEvidenceMatches(objective, match[1]) {
			return true
		}
	}
	return false
}

func objectiveProofMatches(objective, args, output string) bool {
	if !objectiveProofRE.MatchString(output) {
		return false
	}
	if !hasObjectiveExecutionProbe(objective, args) {
		return false
	}
	for _, match := range requestMarkerRE.FindAllStringSubmatch(args, -1) {
		if strings.Contains(output, strings.ToLower(match[1])) {
			return true
		}
	}
	return false
}

func objectiveNegativeMatches(objective, args, output string) bool {
	if !objectiveNegativeRE.MatchString(output) {
		return false
	}
	if !hasObjectiveExecutionProbe(objective, args) {
		return false
	}
	for _, match := range requestMarkerRE.FindAllStringSubmatch(args, -1) {
		if strings.Contains(output, strings.ToLower(match[1])) {
			return true
		}
	}
	return false
}

func AssessOutcome(task database.Task, subtasks []database.Subtask, calls []database.Toolcall, proposed AssessmentStatus, report string) Coverage {
	coverage := Coverage{Status: proposed}
	if !IsAssessmentTask(task.Input) {
		if coverage.Status == "" {
			coverage.Status = OutcomeFailed
		}
		return coverage
	}
	usedSubtasks := make(map[int64]struct{})
	for _, key := range mandatoryObjectives(task.Input) {
		var mapped database.Subtask
		for _, subtask := range subtasks {
			if !IsAdministrativeWork(subtask.Title, subtask.Description) && objectiveMatch(key, subtask.Title+" "+subtask.Description) {
				mapped = subtask
				break
			}
		}
		objective := ObjectiveAssessment{Objective: key, Kind: objectiveKind(key), Status: ObjectiveUntested}
		if mapped.ID != 0 {
			usedSubtasks[mapped.ID] = struct{}{}
			objective = matchingEvidence(key, objective.Kind, mapped, calls)
			if mapped.Status != database.SubtaskStatusFinished && objective.Status != ObjectiveUntested {
				objective.Status = ObjectiveInconclusive
			}
		}
		coverage.ObjectiveResults = append(coverage.ObjectiveResults, objective)
	}
	for _, subtask := range subtasks {
		if IsAdministrativeWork(subtask.Title, subtask.Description) {
			if strings.Contains(strings.ToLower(subtask.Title+" "+subtask.Description), "report") || strings.Contains(strings.ToLower(subtask.Title+" "+subtask.Description), "documentation") {
				status := ObjectiveUntested
				if subtask.Status == database.SubtaskStatusFinished {
					status = ObjectiveVerified
				}
				coverage.ObjectiveResults = append(coverage.ObjectiveResults, ObjectiveAssessment{
					Objective: subtask.Title, Kind: ObjectiveReporting, Status: status, SubtaskID: subtask.ID,
				})
			}
			continue
		}
		if _, exists := usedSubtasks[subtask.ID]; exists {
			continue
		}
		kind := objectiveKind(subtask.Title + " " + subtask.Description)
		objective := matchingEvidence(subtask.Title, kind, subtask, calls)
		if subtask.Status != database.SubtaskStatusFinished && objective.Status != ObjectiveUntested {
			objective.Status = ObjectiveInconclusive
		}
		coverage.ObjectiveResults = append(coverage.ObjectiveResults, objective)
	}
	for _, objective := range coverage.ObjectiveResults {
		if objective.Kind != ObjectiveReporting {
			coverage.Objectives++
		}
	}
	if coverage.Objectives == 0 {
		coverage.ObjectiveResults = append(coverage.ObjectiveResults, ObjectiveAssessment{
			Objective: "primary assessment objective", Kind: ObjectiveVulnerabilityTesting, Status: ObjectiveUntested,
		})
		coverage.Objectives = 1
	}
	for _, objective := range coverage.ObjectiveResults {
		if objective.Kind != ObjectiveReporting && (objective.Status == ObjectiveVerified || objective.Status == ObjectiveNegativelyTested) {
			coverage.Verified++
		}
	}
	if coverage.Status == "" {
		switch {
		case coverage.Objectives > 0 && coverage.Verified == coverage.Objectives:
			coverage.Status = OutcomeCompleted
		case strings.Contains(strings.ToLower(report), "scope") || strings.Contains(strings.ToLower(report), "authorization") || strings.Contains(strings.ToLower(report), "safety prerequisite"):
			coverage.Status = OutcomeBlocked
		case coverage.Verified > 0:
			coverage.Status = OutcomePartial
		default:
			coverage.Status = OutcomeFailed
		}
	}
	if coverage.Status == OutcomeCompleted && (coverage.Objectives == 0 || coverage.Verified != coverage.Objectives) {
		coverage.Status = OutcomePartial
	}
	if coverage.Status == OutcomeBlocked && coverage.Verified > 0 {
		coverage.Status = OutcomePartial
	}
	if coverage.Status == OutcomeBlocked {
		lowerReport := strings.ToLower(report)
		if !strings.Contains(lowerReport, "scope") && !strings.Contains(lowerReport, "safety") &&
			!strings.Contains(lowerReport, "authorization") && !strings.Contains(lowerReport, "rate limit") &&
			!strings.Contains(lowerReport, "testing window") && !strings.Contains(lowerReport, "source ip") &&
			!strings.Contains(lowerReport, "evidence retention") {
			coverage.Status = OutcomeFailed
		} else {
			for idx := range coverage.ObjectiveResults {
				if coverage.ObjectiveResults[idx].Kind != ObjectiveReporting && coverage.ObjectiveResults[idx].Status == ObjectiveUntested {
					coverage.ObjectiveResults[idx].Status = ObjectiveBlocked
				}
			}
		}
	}
	return coverage
}

func FormatTerminalResult(status AssessmentStatus, result string) string {
	return fmt.Sprintf("ASSESSMENT_STATUS: %s\n\n%s", status, strings.TrimSpace(result))
}

func FormatAssessmentResult(coverage Coverage, result string) string {
	objectives, _ := json.Marshal(coverage.ObjectiveResults)
	return fmt.Sprintf("ASSESSMENT_STATUS: %s\nASSESSMENT_OBJECTIVES: %s\n\n%s", coverage.Status, objectives, strings.TrimSpace(result))
}

func ParseTerminalStatus(result string) AssessmentStatus {
	line, _, _ := strings.Cut(result, "\n")
	const prefix = "ASSESSMENT_STATUS: "
	if strings.HasPrefix(line, prefix) {
		switch status := AssessmentStatus(strings.TrimSpace(strings.TrimPrefix(line, prefix))); status {
		case OutcomeCompleted, OutcomePartial, OutcomeBlocked, OutcomeFailed:
			return status
		}
	}
	return ""
}
