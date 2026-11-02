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
