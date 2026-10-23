package providers

import (
	"pentagi/pkg/database"
	"pentagi/pkg/tools"
)

func sanitizeTaskForReport(task database.Task) database.Task {
	task.Input = sanitizeReportText(task.Input)
	task.Result = sanitizeReportText(task.Result)
	return task
}

func sanitizeSubtasksForReport(subtasks []database.Subtask) []database.Subtask {
	result := make([]database.Subtask, len(subtasks))
	for i, subtask := range subtasks {
		subtask.Title = sanitizeReportText(subtask.Title)
		subtask.Description = sanitizeReportText(subtask.Description)
		subtask.Result = sanitizeReportText(subtask.Result)
		subtask.Context = ""
		result[i] = subtask
	}
	return result
}

func sanitizeReportText(value string) string {
	return tools.RedactCredentialsFromResearchContext(redactPrivateAssessmentContext(value))
}
