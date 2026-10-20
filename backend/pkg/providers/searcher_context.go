package providers

import (
	"pentagi/pkg/database"
	"pentagi/pkg/tools"
)

func sanitizeSearcherContext(
	question string,
	task *database.Task,
	subtask *database.Subtask,
	executionContext string,
) (string, *database.Task, *database.Subtask, string) {
	var searcherTask *database.Task
	if task != nil {
		searcherTask = &database.Task{
			ID: task.ID, Status: task.Status,
			Title: tools.RedactCredentialsFromResearchContext(task.Title),
		}
	}
	var searcherSubtask *database.Subtask
	if subtask != nil {
		searcherSubtask = &database.Subtask{
			ID: subtask.ID, Status: subtask.Status,
			Title: tools.RedactCredentialsFromResearchContext(subtask.Title),
		}
	}

	return tools.RedactCredentialsFromResearchContext(question),
		searcherTask,
		searcherSubtask,
		tools.RedactCredentialsFromResearchContext(executionContext)
}
