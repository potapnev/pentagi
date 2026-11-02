package execution

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pentagi/pkg/database"
	"pentagi/pkg/tools"

	"github.com/stretchr/testify/require"
)

func TestFlowGuardBoundsRepeatedFileInspectionAcrossSubtasks(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Inspect the saved evidence"}`)

	require.False(t, guard.Blocked("file", args, 1))
	guard.Record("file", args, "saved evidence", true, 1)
	require.True(t, guard.Blocked("file", json.RawMessage(`{"message":"Read it again","path":"/work/evidence.txt","action":"read_file"}`), 1))
	require.Equal(t, "saved evidence", guard.PreviousResult("file", args, 1))
}

func TestFlowGuardAllowsOneBoundedInspectionAfterNewTechnicalEvidence(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Inspect"}`)
	guard.Record("file", args, "saved evidence", true, 1)
	guard.Record("terminal", json.RawMessage(`{"input":"curl -i https://fixture.invalid/","cwd":"/work"}`),
		"HTTP/1.1 200 OK\nServer: fixture\n\nSurface marker", true, 1)

	require.False(t, guard.Blocked("file", args, 1))
	guard.Record("file", args, "updated evidence", true, 1)
	guard.Record("terminal", json.RawMessage(`{"input":"curl -i https://fixture.invalid/next","cwd":"/work"}`),
		"HTTP/1.1 200 OK\nServer: fixture\n\nNew surface marker", true, 1)
	require.False(t, guard.Blocked("file", args, 1), "new technical evidence permits a relevant follow-up")
}

func TestFlowGuardStopsChangedReportAndReconciliationRequestsWithoutEvidence(t *testing.T) {
	guard := NewFlowGuard()
	guard.Record("report_result", json.RawMessage(`{"result":"14 requests were observed","message":"Report"}`), "report", true, 1)
	require.True(t, guard.Blocked("report_result", json.RawMessage(`{"result":"Actually 16 requests were observed","message":"Reconcile"}`), 2))

	patchA := json.RawMessage(`{"operations":[{"op":"add","title":"Reconcile request counts"}],"message":"counts differ"}`)
	patchB := json.RawMessage(`{"operations":[{"op":"modify","id":4,"title":"Reconcile conflicting request totals"}],"message":"resolve mismatch"}`)
	guard.Record("subtask_patch", patchA, "plan updated", true, 1)
	require.True(t, guard.Blocked("subtask_patch", patchB, 1))
}

func TestFlowGuardSeedsPriorCompletedDelegationAcrossRestart(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"question":"Inspect and reconcile the same evidence files","message":"Delegate"}`)
	guard.Seed([]database.Toolcall{{
		Name: "pentester", Args: args, Result: "Completed inspection", Status: database.ToolcallStatusFinished, TaskID: sql.NullInt64{Int64: 1, Valid: true},
	}})
	require.True(t, guard.Blocked("pentester", json.RawMessage(`{"message":"Repeat","question":"Inspect and reconcile the same evidence files"}`), 2))
}

func TestFlowGuardReusesDelegationOnlyWithinMatchingAuthorizationScope(t *testing.T) {
	guard := NewFlowGuard()
	guard.SetTaskScope(1, "Authorized security assessment for https://app.fixture.local; read-only checks")
	guard.SetTaskScope(2, "Authorized security assessment for https://app.fixture.local; read-only checks")
	guard.SetTaskScope(3, "Authorized security assessment for https://other.fixture.local; uploads prohibited")
	args := json.RawMessage(`{"question":"Inspect the approved REST surface at https://app.fixture.local","message":"Delegate"}`)
	guard.Record("pentester", args, "completed surface inspection", true, 1)
	require.True(t, guard.Blocked("pentester", args, 2), "same scope shares prior result")
	require.False(t, guard.Blocked("pentester", args, 3), "different authorization bounds get independent work")
}

func TestFlowGuardBoundsFailedAttemptsButAllowsChangedFallback(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"question":"Inspect the in-scope REST surface","message":"Delegate"}`)
	for attempt := 0; attempt < 2; attempt++ {
		permit, _, allowed, err := guard.Acquire(t.Context(), "pentester", args, int64(attempt+1))
		require.NoError(t, err)
		require.True(t, allowed)
		permit.Complete("", false)
	}
	_, previous, allowed, err := guard.Acquire(t.Context(), "pentester", args, 3)
	require.NoError(t, err)
	require.False(t, allowed)
	require.Contains(t, previous, "failed")
	guard.Record("terminal", json.RawMessage(`{"input":"curl -i http://fixture.local/api","cwd":"/work"}`), "HTTP/1.1 200 OK\nServer: fixture", true, 4)
	permit, _, allowed, err := guard.Acquire(t.Context(), "pentester", args, 5)
	require.NoError(t, err)
	require.True(t, allowed, "new evidence reopens a bounded fallback")
	permit.Complete("fallback result", true)
}

func TestFlowGuardRecoveryRestoresEvidenceGeneration(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Read"}`)
	guard.Seed([]database.Toolcall{
		{Name: "file", Args: args, Result: "before test", Status: database.ToolcallStatusFinished, TaskID: sql.NullInt64{Int64: 1, Valid: true}},
		{Name: "terminal", Args: json.RawMessage(`{"input":"curl -i http://fixture.local/check","cwd":"/work"}`), Result: "HTTP/1.1 200 OK\nServer: fixture", Status: database.ToolcallStatusFinished},
	})
	require.False(t, guard.Blocked("file", args, 2), "recovery preserves later evidence and permits one justified reread")
}

func TestFlowGuardDoesNotCountConflictingCountsOrReportsAsTechnicalEvidence(t *testing.T) {
	guard := NewFlowGuard()
	guard.Record("report_result", json.RawMessage(`{"result":"14 vs 16 requests","message":"Reconcile"}`), "14 vs 16", true, 1)
	require.Equal(t, 0, guard.TechnicalEvidenceCount())
}

func TestFlowGuardRecognizesTechnicalActionEvidence(t *testing.T) {
	guard := NewFlowGuard()
	guard.Record("terminal", json.RawMessage(`{"input":"curl -i https://fixture.invalid/","cwd":"/work"}`),
		"HTTP/1.1 403 Forbidden", true, 1)
	require.Equal(t, 0, guard.TechnicalEvidenceCount(), "status alone is not new technical evidence")
	guard.Record("terminal", json.RawMessage(`{"input":"curl -i https://fixture.invalid/","cwd":"/work"}`),
		"HTTP/1.1 403 Forbidden\nServer: fixture", true, 1)
	require.Equal(t, 1, guard.TechnicalEvidenceCount())
}

func TestAssessmentOutcomeRequiresTargetEvidenceForEveryObjective(t *testing.T) {
	task := database.Task{Input: "Authorized web security assessment: test the PHP-to-shell hypotheses."}
	subtasks := []database.Subtask{
		{ID: 1, Title: "Inspect existing evidence files", Description: "Read and reconcile saved reports", Status: database.SubtaskStatusFinished},
		{ID: 2, Title: "Test PHP-to-shell hypothesis", Description: "Send a bounded request to the in-scope fixture and record the response", Status: database.SubtaskStatusFinished},
	}
	calls := []database.Toolcall{{Name: "file", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(1)), Args: json.RawMessage(`{"action":"read_file","path":"/work/report.md"}`), Result: "report"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Equal(t, 1, assessment.Objectives)
	require.Equal(t, 0, assessment.Verified)
}

func TestAssessmentOutcomeCompletesWhenEveryObjectiveHasTargetResponse(t *testing.T) {
	task := database.Task{Input: "Authorized web security assessment"}
	subtasks := []database.Subtask{{ID: 2, Title: "Test PHP-to-shell hypothesis", Status: database.SubtaskStatusFinished}}
	calls := []database.Toolcall{{ID: 7, Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(2)), Args: json.RawMessage(`{"input":"curl -i 'https://fixture.invalid/test?execution_probe=php-to-shell&marker=PHP-shell'","cwd":"/work","message":"Test PHP-to-shell hypothesis with a harmless marker"}`), Result: "HTTP/1.1 200 OK\nPHP execution marker: PHP-shell"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomeCompleted, assessment.Status)
	require.Equal(t, 1, assessment.Verified)
	require.Equal(t, ObjectiveVerified, assessment.ObjectiveResults[0].Status)
	require.Equal(t, []int64{7}, assessment.ObjectiveResults[0].EvidenceIDs)
}

func TestGenericCommandOutputDoesNotVerifyPHPToShellObjective(t *testing.T) {
	task := database.Task{Input: "Authorized PHP-to-shell security assessment"}
	subtasks := []database.Subtask{{ID: 2, Title: "Test PHP-to-shell hypothesis", Status: database.SubtaskStatusFinished}}
	calls := []database.Toolcall{{ID: 8, Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(2)), Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/status?probe=PHP-shell","cwd":"/work","message":"Test PHP-to-shell hypothesis"}`), Result: "HTTP/1.1 200 OK\nCommand output: access denied"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Equal(t, ObjectiveInconclusive, assessment.ObjectiveResults[0].Status)
}

func TestStaticMarkerOrUIDResponseDoesNotVerifyPHPToShellObjective(t *testing.T) {
	task := database.Task{Input: "Authorized PHP-to-shell security assessment"}
	subtasks := []database.Subtask{{ID: 2, Title: "Test PHP-to-shell hypothesis", Status: database.SubtaskStatusFinished}}
	for _, response := range []string{"PHP execution marker: static-content", "uid=1000"} {
		calls := []database.Toolcall{{ID: 9, Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(2)), Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/status","cwd":"/work","message":"Test PHP-to-shell hypothesis"}`), Result: "HTTP/1.1 200 OK\\n" + response}}
		assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
		require.Equal(t, OutcomePartial, assessment.Status, response)
		require.Equal(t, ObjectiveInconclusive, assessment.ObjectiveResults[0].Status, response)
	}
}

func TestReflectedRequestMarkerDoesNotVerifyPHPToShellObjective(t *testing.T) {
	task := database.Task{Input: "Authorized PHP-to-shell security assessment"}
	subtasks := []database.Subtask{{ID: 2, Title: "Test PHP-to-shell hypothesis", Status: database.SubtaskStatusFinished}}
	calls := []database.Toolcall{{ID: 10, Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(2)), Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/reflect?marker=challenge-1234","cwd":"/work","message":"Test PHP-to-shell hypothesis"}`), Result: "HTTP/1.1 200 OK\\nPHP execution marker: challenge-1234"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Equal(t, ObjectiveInconclusive, assessment.ObjectiveResults[0].Status)
}

func TestAssessmentOutcomeKeepsBlockAndFailureTerminalStatesDistinct(t *testing.T) {
	task := database.Task{Input: "Authorized penetration test; scope limits were not supplied"}
	require.Equal(t, OutcomeBlocked, AssessOutcome(task, nil, nil, OutcomeBlocked, "scope and safety prerequisites missing").Status)
	require.Equal(t, OutcomeFailed, AssessOutcome(task, nil, nil, OutcomeFailed, "provider failed").Status)
}

func TestAdministrativeSubtaskIsNotObjectiveEvidence(t *testing.T) {
	require.True(t, IsAdministrativeWork("Reconcile request counts", "Compare conflicting totals in the saved report"))
	require.False(t, IsAdministrativeWork("Test PHP-to-shell hypothesis", "Send a bounded in-scope HTTP request and record the response"))
}

func ptrInt64(value int64) *int64 { return &value }

func TestCompletedAdministrativeSubtaskIsOnlyRecreatedAfterNewTechnicalEvidence(t *testing.T) {
	updated := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	completed := []database.Subtask{{Title: "Reconcile request counts", Description: "Resolve the conflicting request totals", Status: database.SubtaskStatusFinished, TaskID: 1, UpdatedAt: sql.NullTime{Time: updated, Valid: true}}}
	candidate := []tools.SubtaskInfo{{Title: "Reconcile conflicting request totals", Description: "Compare request counts again"}}
	require.Empty(t, FilterRepeatedAdministrativeWork(candidate, completed, nil))
	calls := []database.Toolcall{{Name: "terminal", Status: database.ToolcallStatusFinished, TaskID: sql.NullInt64{Int64: 2, Valid: true}, CreatedAt: sql.NullTime{Time: updated.Add(time.Minute), Valid: true}, Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/","cwd":"/work"}`), Result: "HTTP/1.1 200 OK\nServer: fixture"}}
	require.Len(t, FilterRepeatedAdministrativeWork(candidate, completed, calls), 1)
}

func TestFlowGuardScopesTerminalOperationsToTheTask(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"result":"Task report","message":"Close"}`)
	guard.Record("report_result", args, "report", true, 1)
	require.True(t, guard.Blocked("report_result", args, 2), "identical report work is Flow-wide")
}

func TestFlowGuardBoundsEquivalentFileReadsAcrossTasks(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Read evidence"}`)
	for i := int64(1); i <= 15; i++ {
		if i == 1 {
			require.False(t, guard.Blocked("file", args, i))
			guard.Record("file", args, "same file contents", true, i)
			continue
		}
		require.True(t, guard.Blocked("file", args, i), "read %d in Task %d", i, i)
	}
}

func TestFlowGuardMatchesFileToolAndTerminalReadSemantics(t *testing.T) {
	guard := NewFlowGuard()
	guard.Record("file", json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Read"}`), "contents", true, 1)
	terminalRead := json.RawMessage(`{"input":"cat evidence.txt","cwd":"/work","message":"Inspect same file"}`)
	fileKey, fileOK := workSignature("file", json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Read"}`), 1)
	terminalKey, terminalOK := workSignature("terminal", terminalRead, 2)
	require.True(t, fileOK)
	require.True(t, terminalOK)
	require.Equal(t, fileKey, terminalKey)
	require.True(t, guard.Blocked("terminal", terminalRead, 2))
}

func TestFlowGuardFileWriteInvalidatesPriorRead(t *testing.T) {
	guard := NewFlowGuard()
	read := json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Read"}`)
	guard.Record("file", read, "old contents", true, 1)
	require.True(t, guard.Blocked("file", read, 2))
	write := json.RawMessage(`{"action":"write_file","path":"/work/evidence.txt","content":"new contents","message":"Update evidence"}`)
	guard.Record("file", write, "wrote file", true, 3)
	require.False(t, guard.Blocked("file", read, 4), "changed content can be read again")
}

func TestFlowGuardRelativeTerminalWriteInvalidatesPriorRead(t *testing.T) {
	guard := NewFlowGuard()
	read := json.RawMessage(`{"action":"read_file","path":"/work/evidence.txt","message":"Read"}`)
	guard.Record("file", read, "old contents", true, 1)
	write := json.RawMessage(`{"input":"printf updated | tee evidence.txt","cwd":"/work"}`)
	guard.Record("terminal", write, "updated", true, 2)
	require.False(t, guard.Blocked("file", read, 3), "relative terminal write changes /work/evidence.txt")
}

func TestFlowGuardSerializesConcurrentEquivalentCalls(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"action":"read_file","path":"/work/concurrent.txt","message":"Read"}`)
	first, previous, ok, err := guard.Acquire(t.Context(), "file", args, 1)
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, previous)
	result := make(chan struct {
		permit   *WorkPermit
		previous string
		ok       bool
		err      error
	}, 1)
	go func() {
		permit, previous, ok, err := guard.Acquire(t.Context(), "file", args, 2)
		result <- struct {
			permit   *WorkPermit
			previous string
			ok       bool
			err      error
		}{permit, previous, ok, err}
	}()
	key, _ := workSignature("file", args, 0)
	require.Eventually(t, func() bool {
		guard.mu.Lock()
		defer guard.mu.Unlock()
		return guard.seen[key].waiters == 1
	}, time.Second, time.Millisecond)
	first.Complete("contents", true)
	second := <-result
	require.NoError(t, second.err)
	require.False(t, second.ok)
	require.Nil(t, second.permit)
	require.Equal(t, "contents", second.previous)
}

func TestGenericWordPressRESTResponseDoesNotVerifyPHPToShellObjective(t *testing.T) {
	task := database.Task{Input: "Authorized security assessment: inspect WordPress REST headers and test the PHP-to-shell vulnerability hypothesis"}
	subtasks := []database.Subtask{
		{ID: 4, Title: "Inspect WordPress REST endpoint headers", Description: "Record response headers", Status: database.SubtaskStatusFinished},
		{ID: 5, Title: "Write assessment report", Description: "Document the findings", Status: database.SubtaskStatusFinished},
	}
	calls := []database.Toolcall{{ID: 9, Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(4)), Args: json.RawMessage(`{"input":"curl -I http://fixture.local/wp-json/wp/v2/","cwd":"/work","message":"Check response headers"}`), Result: "HTTP/1.1 200 OK"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	found := false
	for _, objective := range assessment.ObjectiveResults {
		if objective.Objective == "php-to-shell" {
			found = true
			require.Equal(t, ObjectiveUntested, objective.Status)
		}
		if objective.Kind == ObjectiveReporting {
			require.Equal(t, ObjectiveVerified, objective.Status)
		}
	}
	require.True(t, found)
}

func TestAssessmentCoverageDistinguishesInconclusiveObjective(t *testing.T) {
	task := database.Task{Input: "Authorized PHP-to-shell security assessment"}
	subtasks := []database.Subtask{{ID: 2, Title: "Test PHP-to-shell hypothesis", Status: database.SubtaskStatusFinished}}
	calls := []database.Toolcall{{ID: 3, Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(2)), Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/","cwd":"/work","message":"Test PHP-to-shell hypothesis"}`), Result: "HTTP/1.1 200 OK"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Equal(t, ObjectiveInconclusive, assessment.ObjectiveResults[0].Status)
}

func TestLocalHTTPFixtureMapsResponsesToPHPToShellObjective(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wp-json/wp/v2/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"namespaces":["wp/v2"]}`))
		case "/php-shell-negative":
			w.WriteHeader(http.StatusOK)
			if r.URL.Query().Get("execution_probe") == "php-to-shell" {
				_, _ = w.Write([]byte("marker " + r.URL.Query().Get("marker") + " not executed"))
			} else {
				_, _ = w.Write([]byte("Reflected marker: " + r.URL.Query().Get("marker")))
			}
		case "/php-shell-positive":
			w.WriteHeader(http.StatusOK)
			if r.URL.Query().Get("execution_probe") == "php-to-shell" {
				_, _ = w.Write([]byte("PHP execution marker: " + r.URL.Query().Get("marker")))
			} else {
				_, _ = w.Write([]byte("Reflected marker: " + r.URL.Query().Get("marker")))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer fixture.Close()

	request := func(path, message string, id, subtaskID int64) database.Toolcall {
		response, err := http.Get(fixture.URL + path)
		require.NoError(t, err)
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		require.NoError(t, err)
		return database.Toolcall{ID: id, Name: "browser", Status: database.ToolcallStatusFinished,
			SubtaskID: database.Int64ToNullInt64(ptrInt64(subtaskID)),
			Args:      json.RawMessage(fmt.Sprintf(`{"url":%q,"action":"html","message":%q}`, fixture.URL+path, message)),
			Result:    fmt.Sprintf("HTTP/1.1 %s\n%s", response.Status, body)}
	}

	task := database.Task{Input: "Authorized security assessment: test PHP-to-shell hypothesis"}
	wpSubtask := database.Subtask{ID: 1, Title: "Discover WordPress REST API", Status: database.SubtaskStatusFinished}
	wp := request("/wp-json/wp/v2/", "Inspect REST surface", 1, 1)
	assessment := AssessOutcome(task, []database.Subtask{wpSubtask}, []database.Toolcall{wp}, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Equal(t, ObjectiveUntested, assessment.ObjectiveResults[0].Status)

	objectiveSubtask := database.Subtask{ID: 2, Title: "Test PHP-to-shell hypothesis", Description: "Send a harmless probe and compare marker response", Status: database.SubtaskStatusFinished}
	negative := request("/php-shell-negative?execution_probe=php-to-shell&marker=fixture-negative-01", "Test PHP-to-shell hypothesis with harmless marker", 2, 2)
	assessment = AssessOutcome(task, []database.Subtask{objectiveSubtask}, []database.Toolcall{negative}, OutcomeCompleted, "")
	require.Equal(t, OutcomeCompleted, assessment.Status)
	require.Equal(t, ObjectiveNegativelyTested, assessment.ObjectiveResults[0].Status)
	serialized := FormatAssessmentResult(assessment, "controlled fixture result")
	require.Equal(t, OutcomeCompleted, ParseTerminalStatus(serialized))
	require.Contains(t, serialized, `"evidence_ids":[2]`)
	require.Contains(t, serialized, `"status":"negatively_tested"`)

	reflected := request("/php-shell-positive?marker=fixture-reflected-01", "Test PHP-to-shell hypothesis with harmless marker", 3, 2)
	assessment = AssessOutcome(task, []database.Subtask{objectiveSubtask}, []database.Toolcall{reflected}, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Equal(t, ObjectiveInconclusive, assessment.ObjectiveResults[0].Status)

	positive := request("/php-shell-positive?execution_probe=php-to-shell&marker=fixture-positive-01", "Test PHP-to-shell hypothesis with harmless marker", 4, 2)
	assessment = AssessOutcome(task, []database.Subtask{objectiveSubtask}, []database.Toolcall{positive}, OutcomeCompleted, "")
	require.Equal(t, ObjectiveVerified, assessment.ObjectiveResults[0].Status)
}

func TestAssessmentWithoutAnObjectiveSubtaskCannotCompleteFromUnrelatedEvidence(t *testing.T) {
	task := database.Task{Input: "Authorized web security assessment"}
	calls := []database.Toolcall{{Name: "terminal", Status: database.ToolcallStatusFinished, Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/health","cwd":"/work"}`), Result: "HTTP/1.1 200 OK\nServer: fixture"}}
	assessment := AssessOutcome(task, []database.Subtask{{ID: 1, Title: "Reconcile request counts", Description: "Review report totals", Status: database.SubtaskStatusFinished}}, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Equal(t, 1, assessment.Objectives)
	require.Zero(t, assessment.Verified)
}

func TestFlowGuardBoundsRepeatedReportingMeasurably(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"result":"14 requests were observed","message":"Write report"}`)
	actualReports := 0
	for i := 0; i < 5; i++ {
		if guard.Blocked("report_result", args, 9) {
			continue
		}
		actualReports++
		guard.Record("report_result", args, "report", true, 9)
	}
	require.Equal(t, 1, actualReports)
	require.Equal(t, 4, guard.Stats()["duplicate_operations_blocked"])
}

func TestFlowGuardAllowsDistinctTechnicalPlanUpdates(t *testing.T) {
	guard := NewFlowGuard()
	first := json.RawMessage(`{"operations":[{"op":"add","title":"Test PHP handler","description":"Send an in-scope request and capture response"}],"message":"Plan next test"}`)
	second := json.RawMessage(`{"operations":[{"op":"add","title":"Test shell boundary","description":"Send a distinct in-scope request"}],"message":"Plan next test"}`)
	guard.Record("subtask_patch", first, "objective added", true, 1)
	require.False(t, guard.Blocked("subtask_patch", second, 1))
}

//go:embed testdata/flow81-baseline-sanitized.json
var flow81Baseline embed.FS

func TestCompletedFlow81RepeatedInspectionReplayIsBounded(t *testing.T) {
	var baseline struct {
		SourceStatus              string `json:"source_status"`
		MaximumSameSignatureCalls int    `json:"maximum_same_signature_calls"`
	}
	fixture, err := flow81Baseline.ReadFile("testdata/flow81-baseline-sanitized.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(fixture, &baseline))
	require.Equal(t, "finished", baseline.SourceStatus)
	guard := NewFlowGuard()
	args := json.RawMessage(`{"action":"read_file","path":"/work/<redacted-evidence-file>","message":"Review evidence"}`)
	actual, blocked := 0, 0
	for i := 0; i < baseline.MaximumSameSignatureCalls; i++ {
		if guard.Blocked("file", args, 81) {
			blocked++
			continue
		}
		actual++
		guard.Record("file", args, "sanitized saved artifact", true, 81)
	}
	require.Equal(t, 1, actual, "the repeated operation executes once")
	require.Equal(t, baseline.MaximumSameSignatureCalls-1, blocked)
	require.InDelta(t, 93.3, float64(blocked)/float64(baseline.MaximumSameSignatureCalls)*100, 0.1)
}

func TestAssessmentDoesNotCompleteFailedObjectiveSubtaskEvenWithTargetResponse(t *testing.T) {
	task := database.Task{Input: "Authorized web security assessment"}
	subtasks := []database.Subtask{{ID: 2, Title: "Test PHP-to-shell hypothesis", Status: database.SubtaskStatusFailed}}
	calls := []database.Toolcall{{Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(2)), Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/test","cwd":"/work"}`), Result: "HTTP/1.1 403 Forbidden"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomePartial, assessment.Status)
	require.Zero(t, assessment.Verified)
}

func TestAssessmentRejectsUnsupportedBlockedClaim(t *testing.T) {
	task := database.Task{Input: "Authorized penetration test"}
	assessment := AssessOutcome(task, nil, nil, OutcomeBlocked, "No work was done.")
	require.Equal(t, OutcomeFailed, assessment.Status)
}
