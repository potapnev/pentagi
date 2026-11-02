package execution

import (
	"database/sql"
	"embed"
	"encoding/json"
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
		"HTTP/1.1 200 OK", true, 1)

	require.False(t, guard.Blocked("file", args, 1))
	guard.Record("file", args, "updated evidence", true, 1)
	guard.Record("terminal", json.RawMessage(`{"input":"curl -i https://fixture.invalid/next","cwd":"/work"}`),
		"HTTP/1.1 200 OK", true, 1)
	require.True(t, guard.Blocked("file", args, 1), "new evidence cannot reset the per-signature cap")
}

func TestFlowGuardStopsChangedReportAndReconciliationRequestsWithoutEvidence(t *testing.T) {
	guard := NewFlowGuard()
	guard.Record("report_result", json.RawMessage(`{"result":"14 requests were observed","message":"Report"}`), "report", true, 1)
	require.True(t, guard.Blocked("report_result", json.RawMessage(`{"result":"Actually 16 requests were observed","message":"Reconcile"}`), 1))

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
	require.True(t, guard.Blocked("pentester", json.RawMessage(`{"message":"Repeat","question":"Inspect and reconcile the same evidence files"}`), 1))
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
	calls := []database.Toolcall{{Name: "terminal", Status: database.ToolcallStatusFinished, SubtaskID: database.Int64ToNullInt64(ptrInt64(2)), Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/test","cwd":"/work"}`), Result: "HTTP/1.1 403 Forbidden"}}
	assessment := AssessOutcome(task, subtasks, calls, OutcomeCompleted, "")
	require.Equal(t, OutcomeCompleted, assessment.Status)
	require.Equal(t, 1, assessment.Verified)
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
	calls := []database.Toolcall{{Name: "terminal", Status: database.ToolcallStatusFinished, TaskID: sql.NullInt64{Int64: 1, Valid: true}, CreatedAt: sql.NullTime{Time: updated.Add(time.Minute), Valid: true}, Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/","cwd":"/work"}`), Result: "HTTP/1.1 200 OK"}}
	require.Len(t, FilterRepeatedAdministrativeWork(candidate, completed, calls), 1)
}

func TestFlowGuardScopesTerminalOperationsToTheTask(t *testing.T) {
	guard := NewFlowGuard()
	args := json.RawMessage(`{"result":"Task report","message":"Close"}`)
	guard.Record("report_result", args, "report", true, 1)
	require.False(t, guard.Blocked("report_result", args, 2), "a new task in the same Flow needs its own report")
}

func TestAssessmentWithoutAnObjectiveSubtaskCannotCompleteFromUnrelatedEvidence(t *testing.T) {
	task := database.Task{Input: "Authorized web security assessment"}
	calls := []database.Toolcall{{Name: "terminal", Status: database.ToolcallStatusFinished, Args: json.RawMessage(`{"input":"curl -i https://fixture.invalid/health","cwd":"/work"}`), Result: "HTTP/1.1 200 OK"}}
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
