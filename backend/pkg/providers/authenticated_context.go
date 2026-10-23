package providers

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/vxcontrol/langchaingo/llms"
	"pentagi/pkg/database"
	"pentagi/pkg/tools"
)

var privateAssessmentContextRE = regexp.MustCompile(`(?s)<authorized_assessment_context>.*?</authorized_assessment_context>`)

// requiresAuthenticatedAssessment limits access to the original private task
// input to a subtask that explicitly performs authenticated assessment work.
// Both records are fetched under the current flow and must retain their parent
// relationship before this predicate is used.
func requiresAuthenticatedAssessment(task database.Task, subtask database.Subtask) bool {
	if task.ID == 0 || subtask.ID == 0 || subtask.TaskID != task.ID || task.FlowID == 0 {
		return false
	}
	taskText := strings.ToLower(task.Title + "\n" + task.Input)
	subtaskText := strings.ToLower(subtask.Title + "\n" + subtask.Description)
	if !containsAny(taskText, "assessment", "pentest", "security test", "vulnerability") ||
		!containsAny(taskText, "credential", "password", "login", "log in", "authenticate", "account", "token") {
		return false
	}
	return containsAny(subtaskText,
		"authenticated", "authenticate", "authentication", "credential", "login", "log in", "sign in", "account access")
}

func containsAny(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func redactPrivateAssessmentContext(value string) string {
	return privateAssessmentContextRE.ReplaceAllString(value, "<authorized_assessment_context>[REDACTED]</authorized_assessment_context>")
}

func redactPrivateAssessmentChain(chain []llms.MessageContent) []llms.MessageContent {
	copy := append([]llms.MessageContent(nil), chain...)
	for i := range copy {
		copy[i].Parts = append([]llms.ContentPart(nil), copy[i].Parts...)
		for j, part := range copy[i].Parts {
			switch text := part.(type) {
			case llms.TextContent:
				text.Text = tools.RedactCredentialsFromResearchContext(redactPrivateAssessmentContext(text.Text))
				copy[i].Parts[j] = text
			case *llms.TextContent:
				if text != nil {
					redacted := *text
					redacted.Text = tools.RedactCredentialsFromResearchContext(redactPrivateAssessmentContext(redacted.Text))
					copy[i].Parts[j] = &redacted
				}
			}
		}
	}
	return copy
}

func marshalChainForStorage(chain []llms.MessageContent) ([]byte, error) {
	return json.Marshal(redactPrivateAssessmentChain(chain))
}

func pentesterUserContext(task *database.Task, subtask *database.Subtask, question, executionContext string) map[string]any {
	authorizedContext := ""
	if task != nil && subtask != nil && requiresAuthenticatedAssessment(*task, *subtask) {
		authorizedContext = task.Input
	} else {
		question = tools.RedactCredentialsFromResearchContext(question)
	}
	return map[string]any{
		"Question":                    question,
		"AuthorizedAssessmentContext": authorizedContext,
		"ExecutionContext":            tools.RedactCredentialsFromResearchContext(executionContext),
	}
}
