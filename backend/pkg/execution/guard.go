package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/tools"
)

const maxAdministrativeExecutions = 2

type AssessmentStatus string

const (
	OutcomeCompleted AssessmentStatus = "COMPLETED"
	OutcomePartial   AssessmentStatus = "PARTIAL"
	OutcomeBlocked   AssessmentStatus = "BLOCKED"
	OutcomeFailed    AssessmentStatus = "FAILED"
)

type Coverage struct {
	Status     AssessmentStatus
	Objectives int
	Verified   int
}

type workEntry struct {
	count        int
	evidenceAt   int
	previousText string
}

// FlowGuard shares repeat history across agent chains and subtasks belonging to one Flow.
type FlowGuard struct {
	mu       sync.Mutex
	seen     map[string]workEntry
	evidence int
	adminOps int
	blocked  int
}

func NewFlowGuard() *FlowGuard { return &FlowGuard{seen: make(map[string]workEntry)} }

func (g *FlowGuard) Blocked(name string, args json.RawMessage, taskID int64) bool {
	key, ok := workSignature(name, args, taskID)
	if !ok {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, exists := g.seen[key]
	blocked := exists && (entry.count >= maxAdministrativeExecutions || entry.evidenceAt == g.evidence)
	if blocked {
		g.blocked++
	}
	return blocked
}

func (g *FlowGuard) PreviousResult(name string, args json.RawMessage, taskID int64) string {
	key, ok := workSignature(name, args, taskID)
	if !ok {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.seen[key].previousText
}

func (g *FlowGuard) Record(name string, args json.RawMessage, result string, succeeded bool, taskID int64) {
	if !succeeded {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if isTechnicalEvidence(name, args, result) {
		g.evidence++
	}
	key, ok := workSignature(name, args, taskID)
	if !ok {
		return
	}
	entry := g.seen[key]
	entry.count++
	g.adminOps++
	entry.evidenceAt = g.evidence
	entry.previousText = result
	g.seen[key] = entry
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

func isTechnicalEvidence(name string, args json.RawMessage, result string) bool {
	if strings.TrimSpace(result) == "" || strings.Contains(strings.ToLower(result), "connection refused") || strings.Contains(strings.ToLower(result), "could not resolve host") {
		return false
	}
	switch name {
	case "terminal":
		var action tools.TerminalAction
		if json.Unmarshal(args, &action) != nil || !toolCommandRE.MatchString(action.Input) {
			return false
		}
		return httpStatusRE.MatchString(result) || strings.Contains(strings.ToLower(result), "open") || strings.Contains(strings.ToLower(result), "matches")
	case "browser":
		var action tools.Browser
		if json.Unmarshal(args, &action) != nil || !(strings.HasPrefix(action.Url, "http://") || strings.HasPrefix(action.Url, "https://")) {
			return false
		}
		return httpStatusRE.MatchString(result) || strings.Contains(strings.ToLower(result), "<html") || strings.Contains(strings.ToLower(result), "# ")
	default:
		return false
	}
}

func workSignature(name string, args json.RawMessage, taskID int64) (string, bool) {
	var fields map[string]any
	if json.Unmarshal(args, &fields) != nil {
		return "", false
	}
	delete(fields, "message")
	switch name {
	case "file":
		if fields["action"] != string(tools.ReadFile) {
			return "", false
		}
	case "terminal":
		var action tools.TerminalAction
		if json.Unmarshal(args, &action) != nil || !adminCommandRE.MatchString(action.Input) || toolCommandRE.MatchString(action.Input) {
			return "", false
		}
		fields = map[string]any{"input": strings.Join(strings.Fields(action.Input), " "), "cwd": action.Cwd}
	case "report_result", "subtask_list":
		fields = map[string]any{"operation": name}
	case "subtask_patch":
		var patch tools.SubtaskPatch
		if json.Unmarshal(args, &patch) == nil && len(patch.Operations) > 0 {
			adminOnly := true
			for _, operation := range patch.Operations {
				if (operation.Op != tools.SubtaskOpAdd && operation.Op != tools.SubtaskOpModify) || !IsAdministrativeWork(operation.Title, operation.Description) {
					adminOnly = false
					break
				}
			}
			if adminOnly {
				fields = map[string]any{"operation": "administrative-subtask-patch"}
			}
		}
	case "pentester", "coder", "maintenance":
		// These are delegated work requests; the message field is commentary, not scope.
	default:
		return "", false
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(append([]byte(name+":"), canonical...))
	return fmt.Sprintf("%d:%s", taskID, hex.EncodeToString(sum[:])), true
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
			if prior.valid && call.TaskID.Valid && call.TaskID.Int64 == prior.taskID && call.CreatedAt.Valid && call.CreatedAt.Time.After(prior.at) && call.Status == database.ToolcallStatusFinished && isTechnicalEvidence(call.Name, call.Args, call.Result) {
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
	return false
}

func isObjective(title, description string) bool { return !IsAdministrativeWork(title, description) }

func hasSubtaskEvidence(id int64, calls []database.Toolcall) bool {
	for _, call := range calls {
		if call.SubtaskID.Valid && call.SubtaskID.Int64 == id && call.Status == database.ToolcallStatusFinished && isTechnicalEvidence(call.Name, call.Args, call.Result) {
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
	for _, subtask := range subtasks {
		if !isObjective(subtask.Title, subtask.Description) {
			continue
		}
		coverage.Objectives++
		if subtask.Status == database.SubtaskStatusFinished && hasSubtaskEvidence(subtask.ID, calls) {
			coverage.Verified++
		}
	}
	if coverage.Objectives == 0 && IsAssessmentTask(task.Input) {
		coverage.Objectives = 1
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
		}
	}
	return coverage
}

func FormatTerminalResult(status AssessmentStatus, result string) string {
	return fmt.Sprintf("ASSESSMENT_STATUS: %s\n\n%s", status, strings.TrimSpace(result))
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
