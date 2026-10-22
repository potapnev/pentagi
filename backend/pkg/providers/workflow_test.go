package providers

import (
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/tools"

	"github.com/stretchr/testify/require"
)

func TestGeneratedAssessmentPhasesRemainDistinctAndOrdered(t *testing.T) {
	task := database.Task{
		Title: "API Security Assessment",
		Input: "Assess http://fixture.invalid/api using the authorized test accounts.",
	}
	generated := []tools.SubtaskInfo{
		{Title: "Map API", Description: "Identify documented routes"},
		{Title: "Establish identities", Description: "Authenticate the supplied test accounts"},
		{Title: "Compare access", Description: "Compare owner and cross-account reads"},
		{Title: "Check controls", Description: "Check owner-only and unauthenticated controls"},
		{Title: "Preserve evidence", Description: "Save request and response evidence"},
		{Title: "Submit findings", Description: "Submit supported findings"},
		{Title: "Report coverage", Description: "Report verified outcomes and gaps"},
	}

	got := applyGeneratedPhasePolicy(task, generated)
	require.Len(t, generated, 7, "fixture represents the original generated phase count")
	require.Equal(t, generated, got, "candidate must preserve every generated phase in its original order")
	seen := make(map[string]bool, len(got))
	for _, phase := range got {
		require.NotEmpty(t, phase.Title)
		require.False(t, seen[phase.Title], "phase title must be distinct: %s", phase.Title)
		seen[phase.Title] = true
	}
}

func TestPhasePreservationDoesNotChangeMultiTargetPlans(t *testing.T) {
	task := database.Task{Title: "Web Assessment", Input: "Assess https://one.invalid and https://two.invalid"}
	generated := []tools.SubtaskInfo{{Title: "First"}, {Title: "Second"}}
	require.Equal(t, generated, applyGeneratedPhasePolicy(task, generated))
}
