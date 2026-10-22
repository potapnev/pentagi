package providers

import (
	"pentagi/pkg/database"
	"pentagi/pkg/tools"
)

// applyGeneratedPhasePolicy preserves each generated phase as an independent
// scheduled subtask for the controller to execute and track.
func applyGeneratedPhasePolicy(_ database.Task, plan []tools.SubtaskInfo) []tools.SubtaskInfo {
	return plan
}
