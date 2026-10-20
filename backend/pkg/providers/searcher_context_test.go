package providers

import (
	"strings"
	"testing"

	"pentagi/pkg/database"
)

func TestSanitizeSearcherContextSeparatesSecretsFromResearchScope(t *testing.T) {
	task := &database.Task{
		ID:    7,
		Title: "Test accounts: alice@example.test / Alice-Secret-17!",
		Input: "alice@example.test / Alice-Secret-17!",
	}
	subtask := &database.Subtask{
		ID:          9,
		Title:       "Inspect https://api.example.test/docs",
		Context:     "Credentials:\n- bob@example.test: Bob-Secret-29!\nScope: https://app.example.test and https://api.example.test:8443; inspect /docs.",
		Description: "bob@example.test / Bob-Secret-29!",
	}
	question := "Research this issue; password: Alice-Secret-17!"
	executionContext := subtask.Context

	gotQuestion, gotTask, gotSubtask, gotExecutionContext := sanitizeSearcherContext(question, task, subtask, executionContext)
	combined := strings.Join([]string{gotQuestion, gotTask.Title, gotSubtask.Title, gotExecutionContext}, "\n")
	for _, secret := range []string{"Alice-Secret-17!", "Bob-Secret-29!", "alice@example.test", "bob@example.test"} {
		if strings.Contains(combined, secret) {
			t.Errorf("Searcher context exposed credential %q", secret)
		}
	}
	for _, scope := range []string{"https://app.example.test", "https://api.example.test:8443", "/docs"} {
		if !strings.Contains(combined, scope) {
			t.Errorf("Searcher context lost authorized scope %q; context=%q", scope, combined)
		}
	}
	if gotTask.Input != "" || gotTask.Result != "" || gotSubtask.Context != "" || gotSubtask.Description != "" || gotSubtask.Result != "" {
		t.Fatal("Searcher's task projection retained fields outside the prompt contract")
	}
}

func TestSanitizeSearcherContextSupportsTaskWithoutDocsOrSubtask(t *testing.T) {
	task := &database.Task{ID: 4, Title: "Assess https://service.example.test"}
	question, gotTask, gotSubtask, context := sanitizeSearcherContext("Find public product documentation", task, nil, "Scope: https://service.example.test; no docs lead is known.")
	if gotSubtask != nil {
		t.Fatal("unexpected subtask in task-level research context")
	}
	for _, want := range []string{"Find public product documentation", gotTask.Title, "https://service.example.test", "no docs lead is known"} {
		if !strings.Contains(strings.Join([]string{question, gotTask.Title, context}, "\n"), want) {
			t.Errorf("task-level search context lost %q; context=%q task=%q", want, strings.Join([]string{question, gotTask.Title, context}, "\n"), gotTask.Title)
		}
	}
}
