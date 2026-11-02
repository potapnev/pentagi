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
