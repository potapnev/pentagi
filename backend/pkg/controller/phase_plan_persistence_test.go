package controller

import (
	"context"
	"testing"

	"pentagi/pkg/database"
	"pentagi/pkg/providers"
	"pentagi/pkg/tools"

	"github.com/stretchr/testify/require"
)

type matchedPlanProvider struct {
	providers.FlowProvider
	plan []tools.SubtaskInfo
}

func (p matchedPlanProvider) GenerateSubtasks(context.Context, int64) ([]tools.SubtaskInfo, error) {
	return p.plan, nil
}

func (matchedPlanProvider) PrepareAgentChain(_ context.Context, _, subtaskID int64) (int64, error) {
	return subtaskID + 100, nil
}

type matchedPlanStore struct {
	database.Querier
	rows []database.Subtask
}

func (q *matchedPlanStore) CreateSubtask(_ context.Context, arg database.CreateSubtaskParams) (database.Subtask, error) {
	row := database.Subtask{ID: int64(len(q.rows) + 1), TaskID: arg.TaskID, Status: arg.Status, Title: arg.Title, Description: arg.Description}
	q.rows = append(q.rows, row)
	return row, nil
}

func (q *matchedPlanStore) GetTaskSubtasks(context.Context, int64) ([]database.Subtask, error) {
	return append([]database.Subtask(nil), q.rows...), nil
}

func (q *matchedPlanStore) GetTaskPlannedSubtasks(_ context.Context, taskID int64) ([]database.Subtask, error) {
	var rows []database.Subtask
	for _, row := range q.rows {
		if row.TaskID == taskID && (row.Status == database.SubtaskStatusCreated || row.Status == database.SubtaskStatusWaiting) {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func TestGeneratedPhasesPersistWithDistinctIDsAndRunInOrder(t *testing.T) {
	ctx := context.Background()
	plan := []tools.SubtaskInfo{
		{Title: "Map API", Description: "Identify documented routes"},
		{Title: "Establish identities", Description: "Authenticate the supplied test accounts"},
		{Title: "Compare access", Description: "Compare owner and cross-account reads"},
		{Title: "Check controls", Description: "Check owner-only and unauthenticated controls"},
		{Title: "Preserve evidence", Description: "Save request and response evidence"},
		{Title: "Submit findings", Description: "Submit supported findings"},
		{Title: "Report coverage", Description: "Report verified outcomes and gaps"},
	}
	q := &matchedPlanStore{}
	stc := NewSubtaskController(&TaskContext{
		TaskID: 5, TaskTitle: "Assessment", TaskInput: "Assess the authorized fixture",
		FlowContext: FlowContext{DB: q, Provider: matchedPlanProvider{plan: plan}},
	})

	require.NoError(t, stc.GenerateSubtasks(ctx))
	require.Len(t, q.rows, len(plan))
	seenIDs := make(map[int64]bool, len(q.rows))
	for i, row := range q.rows {
		require.Equal(t, int64(i+1), row.ID)
		require.False(t, seenIDs[row.ID], "database task identity must be unique")
		seenIDs[row.ID] = true
		require.Equal(t, plan[i].Title, row.Title)
		require.Equal(t, plan[i].Description, row.Description)
		require.Equal(t, database.SubtaskStatusCreated, row.Status)
	}

	for i := range plan {
		worker, err := stc.PopSubtask(ctx, nil)
		require.NoError(t, err)
		require.NotNil(t, worker)
		require.Equal(t, int64(i+1), worker.GetSubtaskID())
		require.Equal(t, plan[i].Title, worker.GetTitle())
		q.rows[i].Status = database.SubtaskStatusFinished
		remaining, err := q.GetTaskPlannedSubtasks(ctx, 5)
		require.NoError(t, err)
		require.Len(t, remaining, len(plan)-i-1, "finished work leaves later objectives scheduled")
	}

	next, err := stc.PopSubtask(ctx, nil)
	require.NoError(t, err)
	require.Nil(t, next, "only an empty unfinished backlog permits loop completion")
}
