package providers

import (
	"testing"

	"pentagi/pkg/database"

	"github.com/stretchr/testify/require"
)

func TestSanitizeReportContextRemovesPrivateAccounts(t *testing.T) {
	task := sanitizeTaskForReport(database.Task{
		Input:  "Assess the authorized API. Disposable test accounts:\n- Alice: username alice, password Alpha-Secret-71!\n- Bob: username bob, password Beta-Secret-82!",
		Result: "<authorized_assessment_context>password: Alpha-Secret-71!</authorized_assessment_context>",
	})
	require.NotContains(t, task.Input, "alice")
	require.NotContains(t, task.Input, "bob")
	require.NotContains(t, task.Input, "Alpha-Secret-71!")
	require.NotContains(t, task.Input, "Beta-Secret-82!")
	require.NotContains(t, task.Result, "Alpha-Secret-71!")
	require.Contains(t, task.Input, "authorized API")

	subtasks := sanitizeSubtasksForReport([]database.Subtask{{
		Title: "Verify access", Description: "Account username alice password Alpha-Secret-71!",
		Result: "Evidence summary", Context: "password: Alpha-Secret-71!",
	}})
	require.NotContains(t, subtasks[0].Description, "alice")
	require.NotContains(t, subtasks[0].Description, "Alpha-Secret-71!")
	require.Empty(t, subtasks[0].Context)
}
