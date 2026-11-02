package controller

import (
	"context"
	"fmt"

	"pentagi/pkg/database"
)

func readFlowToolcalls(ctx context.Context, db database.Querier, flowID int64) (calls []database.Toolcall, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("read Flow tool-call evidence: %v", recovered)
		}
	}()
	return db.GetFlowToolcalls(ctx, flowID)
}

func readFlowSubtasks(ctx context.Context, db database.Querier, flowID int64) (subtasks []database.Subtask, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("read Flow task history: %v", recovered)
		}
	}()
	tasks, err := db.GetFlowTasks(ctx, flowID)
	if err != nil {
		return nil, err
	}
	for _, task := range tasks {
		current, err := db.GetTaskSubtasks(ctx, task.ID)
		if err != nil {
			return nil, err
		}
		subtasks = append(subtasks, current...)
	}
	return subtasks, nil
}
