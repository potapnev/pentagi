package providers

import (
	"context"
	"fmt"

	"pentagi/pkg/database"
	"pentagi/pkg/execution"

	"github.com/sirupsen/logrus"
)

func (fp *flowProvider) executionWorkGuard(ctx context.Context) *execution.FlowGuard {
	fp.guardOnce.Do(func() {
		guard := execution.NewFlowGuard()
		if fp.db != nil && fp.flowID != 0 {
			if err := fp.loadFlowTaskScopes(ctx, guard); err != nil {
				logrus.WithContext(ctx).WithError(err).WithField("flow_id", fp.flowID).
					Warn("could not seed repeated-work guard with task authorization scopes")
			}
			calls, err := fp.readHistoricalToolcalls(ctx)
			if err != nil {
				logrus.WithContext(ctx).WithError(err).WithField("flow_id", fp.flowID).
					Warn("could not seed repeated-work guard from Flow history; current execution remains bounded")
			} else {
				guard.Seed(calls)
			}
		}
		fp.workGuard = guard
	})
	return fp.workGuard
}

func (fp *flowProvider) loadTaskScope(ctx context.Context, guard *execution.FlowGuard, taskID int64) {
	if taskID == 0 || guard.HasTaskScope(taskID) || fp.db == nil {
		return
	}
	task, err := fp.readTask(ctx, taskID)
	if err != nil {
		logrus.WithContext(ctx).WithError(err).WithField("task_id", taskID).
			Warn("could not read task authorization scope for repeated-work guard")
		return
	}
	guard.SetTaskScope(taskID, task.Input)
}

func (fp *flowProvider) loadFlowTaskScopes(ctx context.Context, guard *execution.FlowGuard) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("read Flow task scopes: %v", recovered)
		}
	}()
	tasks, err := fp.db.GetFlowTasks(ctx, fp.flowID)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		guard.SetTaskScope(task.ID, task.Input)
	}
	return nil
}

func (fp *flowProvider) readTask(ctx context.Context, taskID int64) (task database.Task, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("read task authorization scope: %v", recovered)
		}
	}()
	return fp.db.GetTask(ctx, taskID)
}

// readHistoricalToolcalls tolerates narrow test doubles that embed Querier but
// intentionally leave this unrelated method unimplemented.
func (fp *flowProvider) readHistoricalToolcalls(ctx context.Context) (calls []database.Toolcall, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("read Flow tool-call history: %v", recovered)
		}
	}()
	return fp.db.GetFlowToolcalls(ctx, fp.flowID)
}
